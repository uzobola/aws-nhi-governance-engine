# Threat Model: NHI Governance Engine

This document models the security of the scanner itself. A tool that reads
identity and access configuration across an AWS account is a sensitive workload,
and the obvious question a reviewer asks is: how do you run something with this
reach without it becoming the over-privileged, unaccountable non-human identity
it is built to find? This is the answer, written against the engine as it ships.

## 1. System overview

The engine runs as a scheduled and on-demand GitHub Actions job. It authenticates
to AWS through GitHub's OIDC provider, exchanging a short-lived OIDC token for
temporary STS credentials by assuming the `github-actions-nhi-scan` role. It then
makes read-only IAM and Secrets Manager calls, evaluates the results against a set
of detectors, and writes a findings report (JSON and Markdown) that is published
to the run summary and uploaded as a build artifact.

There are no static AWS access keys anywhere in the repository or the pipeline.
The only configuration value the workflow needs is the role ARN, which is not a
secret and is stored as a repository variable.

## 2. Assets worth protecting

- The read access the scan role holds over IAM and Secrets Manager metadata.
- The findings report, which is effectively a map of the account's identity
  weaknesses (unowned identities, over-privileged roles, loose trust policies).
- The OIDC trust relationship and the scan role's permission set.
- The integrity of the pipeline that produces the findings.

## 3. Trust boundaries

1. **GitHub Actions runner to AWS.** Control passes from GitHub to AWS at the
   OIDC token exchange. AWS STS is the relying party; it decides whether to issue
   credentials based on the role's trust policy conditions.
2. **Repository to AWS permissions.** Whoever can change code or the workflow on
   the trusted ref can change what runs inside the credential session.
3. **Findings output to readers.** Whoever can read the Actions run, its summary,
   or its artifacts can read the account's posture.

## 4. Threats and mitigations

| Threat | Vector | Mitigation | Residual risk |
|---|---|---|---|
| The scanner becomes the over-privileged NHI it hunts | Scope creep in the scan role's policy over time | Least-privilege read-only policy; `--print-policy` is the source of truth and the Terraform role grants exactly that and nothing more; no write, delete, or policy-modifying actions exist in the policy; the role carries an Owner tag and is scanned by the engine on every run | Read access to identity metadata is inherently sensitive |
| Credential theft or long-lived secret | Static keys stored in CI | No static keys anywhere; GitHub OIDC is exchanged for short-lived STS credentials; trust is pinned by `aud` and `sub` conditions | The short-lived STS credential window during a run |
| Unauthorized assumption of the scan role | A fork, a pull-request branch, or an unrelated repository attempts to assume the role | Trust `sub` is scoped to `repo:uzobola/aws-nhi-governance-engine:ref:refs/heads/main`, so only this repository's `main` ref can assume the role; `aud` is pinned to `sts.amazonaws.com`. Pull-request branches and forks cannot assume it | Anyone with push access to the trusted ref |
| Secret value disclosure | Scanner reads secret contents | The policy grants only `secretsmanager:ListSecrets` and `DescribeSecret` (metadata); it does not grant `GetSecretValue`. The engine reads rotation configuration, never secret material | Secret names and metadata are visible |
| Tampering to hide a finding | Suppressing or editing results | Findings are regenerated from live AWS state on every run; the only suppression path is the in-repository, version-controlled exception register, which records a reason, owner, and expiry, shows accepted items in the report rather than deleting them, and time-boxes each acceptance so it lapses back to open | A user with repository write access can add an exception, though it is auditable in git history |
| Findings used for reconnaissance | The report enumerates the account's weaknesses | Artifact and run-summary access follow the repository's visibility and Actions permissions; keep the repository private where posture data is sensitive | Anyone who can read a run can read the posture |
| Supply-chain compromise | Malicious dependency (boto3, PyYAML) or GitHub Action | Minimal dependency surface; Actions pinned to major versions, with a path to pin to commit SHAs for higher assurance | Transitive dependency and Action risk |
| Workflow modification to escalate or exfiltrate | A malicious change to the workflow on the trusted ref | Changes to the trusted ref are gated by branch protection and review; the job is granted only `id-token: write` and `contents: read`, and the role itself confers no privileges that could be used to escalate | Depends on branch protection being enforced |

## 5. Blast radius if the scan role is compromised

This is the bounding case. Suppose the role's short-lived credentials were
somehow captured during a run. For the brief life of that credential, the holder
could enumerate IAM roles, users, attached and inline policies, access-key
metadata, service last-accessed data, and Secrets Manager metadata in this single
account.

They could **not** read any secret value, create, modify, or delete any resource,
change any IAM policy or trust relationship, assume any other role, or establish
persistence such as a new access key. Every action in the policy is a read.

So the worst credible outcome is disclosure of identity and secret-metadata
posture, which is reconnaissance, not modification or destruction, bounded to one
account and to a short credential window. That deliberately small, read-only,
single-account, short-lived blast radius is the design's answer to running a
high-reach scanner safely.

## 6. Residual risks accepted

- The findings report reveals account posture to anyone who can read the run.
  Mitigated by repository visibility and Actions permissions, not eliminated.
- The STS credential is valid for its session lifetime. Reducible by setting a
  shorter `max_session_duration` on the role if a tighter window is wanted.
- Push access to the trusted ref is implicitly trusted. This is the standard
  CI trust assumption and is managed through branch protection and review, not by
  the engine.

## 7. The scanner embodies what it enforces

The scan role is a worked example of every control the engine checks for in other
identities. It has an accountable owner tag. It uses no static credentials. Its
permissions are least-privilege and read-only. Its trust policy is OIDC with both
`aud` and `sub` conditions, scoped to a single repository and ref, which is the
exact configuration the trust-policy detectors flag others for missing. The engine
scans its own identity on every run and reports it clean. The strongest evidence
that these controls are real is that the tool holds itself to them.
