# AWS NHI Governance Engine

Discovers, scores, and governs the non-human identities in an AWS account: IAM roles, access keys, and secrets today, with AI agents on the roadmap. Findings are mapped to the OWASP Non-Human Identities Top 10 and NIST 800-53, and the tool runs as a CI gate that fails a build when it finds a HIGH or CRITICAL identity.

Machine identities now outnumber human ones in most cloud estates by a wide margin, yet far fewer organizations govern the machine-identity lifecycle than the human one. This engine is built for that gap: it treats every workload, role, key, and agent as an identity that needs an owner, a least-privilege boundary, a credible authentication model, and an offboarding path.

## What it does

The engine runs seven detectors over the identities it collects, each producing a control-mapped finding with a severity:

| Detector | Severity | OWASP NHI |
|---|---|---|
| Missing owner | Medium | NHI1:2025 Improper Offboarding |
| Orphaned or stale role | Medium | NHI1:2025 Improper Offboarding |
| Aged access key | High | NHI7:2025 Long-Lived Secrets |
| Static credential model | Medium | NHI4:2025 Insecure Authentication |
| Wildcard policy | High | NHI5:2025 Overprivileged NHI |
| Permissive trust policy | Critical | NHI6:2025 Insecure Cloud Deployment Configurations |
| Unrotated secret | Medium | NHI7:2025 Long-Lived Secrets |

Across those findings it exercises the NIST 800-53 AC-2, AC-6, IA-5, and IA-9 families: account management, least privilege, authenticator and secret management, and service identification and authentication.

### Example finding

The most severe detector catches a role whose trust policy lets any principal assume it. From a demo run (`sample_report.json`):

```json
{
  "finding_id": "NHI-TRUST-WILDCARD:legacy-etl-runner",
  "nhi_id": "arn:aws:iam::000000000000:role/legacy-etl-runner",
  "nhi_type": "iam_role",
  "title": "Role trust policy allows any principal to assume it",
  "severity": "CRITICAL",
  "owasp_nhi": "NHI6:2025 Insecure Cloud Deployment Configurations",
  "nist_800_53": "NIST 800-53 AC-6 (Least Privilege); NIST 800-53 IA-9 (Service Identification and Authentication)",
  "evidence": {
    "trust_statement": { "Effect": "Allow", "Principal": { "AWS": "*" }, "Action": "sts:AssumeRole" }
  },
  "remediation": "Restrict the trust policy to specific, intended principals. This is the cross-account assumption risk your STS/AssumeRole detection pipeline watches for."
}
```

Two things set it apart from a plain linter:

- **Credential-model scoring.** Every identity is scored on how it authenticates, from `STATIC_LONG_LIVED` (a long-lived access key, the worst) through `STS_ASSUMED` to `FEDERATED_OIDC` (short-lived and federated, the target state). The score is what lets the engine prove a remediation actually improved posture rather than just changing a config.
- **It practices what it preaches.** `--print-policy` emits the exact least-privilege, read-only IAM policy the engine itself needs to run, so the scanner is never the most over-privileged identity in the account.

## How it works

```
Collector  ->  Detectors  ->  Reporter
```

A collector gathers identities into a common record, detectors evaluate each record, and the reporter writes a timestamped JSON evidence report. There are two collectors: `AwsCollector` reads a live account over boto3 using read-only calls, and `DemoCollector` runs offline against fixtures so the engine is reviewable without any AWS credentials.

The run exits non-zero when any HIGH or CRITICAL finding is present, which is what lets it gate a pipeline.

## Quickstart

Offline, no credentials needed:

```
pip install -r requirements.txt
python nhi_governance_engine.py --demo --output report.json
```

Against a real account, read-only:

```
python nhi_governance_engine.py --region us-east-1 --output nhi-report.json
```

See the least-privilege policy the engine needs:

```
python nhi_governance_engine.py --print-policy
```

`sample_report.json` in this repo is the output of a demo run, so you can see the evidence format without running anything.

## Phase 2: Workload Identity Federation

The worst finding the engine can raise is a long-lived static access key, so the engine's own CI does not use one. This phase runs the scan through GitHub Actions with OpenID Connect, leaving zero stored AWS keys in the repo. `oidc-federation.tf` provisions the OIDC provider and a role whose trust policy is scoped to a single repository and ref, the deliberate opposite of the wildcard-principal trust the engine flags as critical. The rationale and control mapping are in `PHASE-2.md`; the live proof is below.

### Proof (live run)

The scheduled scan runs entirely on short-lived, federated credentials. The workflow's identity step confirms it:

```
$ aws sts get-caller-identity
{
  "UserId": "AROA...:GitHubActions",
  "Account": "<ACCOUNT_ID>",
  "Arn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/github-actions-nhi-scan/GitHubActions"
}
```

The `assumed-role` ARN and the `AROA` user ID are an STS session, not a static-key IAM user. No AWS access key exists in the repository or in GitHub secrets; the only stored value is the role ARN, which is not sensitive.

The engine flags the very credential model the CI moved off of. Before this phase the scan ran as the `workshop-pipeline` IAM user; that user still appears in the account scored `static_long_lived` under NHI4, which is exactly the finding type the migration resolves for the workload itself.

A before-and-after, run against the live account (account ID redacted, reports kept local per `.gitignore`):

- Before: 9 findings. The scan role itself flagged for no owner; `workshop-pipeline` scored `static_long_lived`.
- After: 8 findings. Scan role clean (Owner tag applied), every finding control-mapped in canonical `NHIx:2025` form.

## Roadmap

| Phase | Status |
|---|---|
| Phase 1: discovery, seven detectors, control mapping, CI gate | Complete |
| Phase 2: workload identity federation (OIDC) | Complete (live run, federated session verified) |
| Access Advisor unused-permissions detector | Planned |
| Cross-account trust and managed-policy resolution | Planned |
| Phase 3: govern an AI agent as a non-human identity (Bedrock AgentCore) | Planned |

## Layout

```
nhi_governance_engine.py                      the engine
requirements.txt                              boto3
oidc-federation.tf                            Phase 2 OIDC provider, role, least-priv policy
.github/workflows/nhi-governance-scan.yml     scheduled scan via OIDC
PHASE-2.md                                    federation rationale and proof loop
sample_report.json                            example evidence output from a demo run
```
