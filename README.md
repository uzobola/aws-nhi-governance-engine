# AWS NHI Governance Engine

Discovers, scores, and governs the non-human identities in an AWS account: IAM roles, users, access keys, and secrets today, with AI agents on the roadmap. Findings are mapped to the OWASP Non-Human Identities Top 10 and NIST 800-53, and the tool runs as a CI gate that fails a build when it finds an unaccepted HIGH or CRITICAL identity.

Machine identities now outnumber human ones in most cloud estates by a wide margin, yet far fewer organizations govern the machine-identity lifecycle than the human one. This engine is built for that gap: it treats every workload, role, key, and agent as an identity that needs an owner, a least-privilege boundary, a credible authentication model, and an offboarding path.

## What it does

The engine runs eleven detectors over the identities it collects, each producing a control-mapped finding with a severity:

| Detector | Severity | OWASP NHI |
|---|---|---|
| Missing owner | Medium | NHI1:2025 Improper Offboarding |
| Orphaned or stale role | Medium | NHI1:2025 Improper Offboarding |
| Aged access key | High | NHI7:2025 Long-Lived Secrets |
| Static credential model | Medium | NHI4:2025 Insecure Authentication |
| Wildcard inline policy | High | NHI5:2025 Overprivileged NHI |
| Admin via attached managed policy | High | NHI5:2025 Overprivileged NHI |
| Unused permissions (Access Advisor last-accessed) | Medium | NHI5:2025 Overprivileged NHI |
| Permissive trust policy (wildcard principal) | Critical | NHI6:2025 Insecure Cloud Deployment Configurations |
| Cross-account trust without ExternalId | High | NHI6:2025 Insecure Cloud Deployment Configurations |
| OIDC trust gaps (missing aud, missing sub, unscoped GitHub sub) | High | NHI4:2025 Insecure Authentication / NHI6:2025 Insecure Cloud Deployment Configurations |
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
  "remediation": "Restrict the trust policy to specific, intended principals."
}
```

Three things set it apart from a plain linter:

- **Credential-model scoring.** Every identity is scored on how it authenticates, from `STATIC_LONG_LIVED` (a long-lived access key, the worst) through `STS_ASSUMED` to `FEDERATED_OIDC` (short-lived and federated, the target state). The score is what lets the engine prove a remediation actually improved posture rather than just changing a config.
- **Evidence over assertion.** The unused-permission detector resolves IAM Access Advisor last-accessed data, so "this role looks over-scoped" becomes "these granted services have never been used," which is the form an auditor or app owner can act on. Managed-policy resolution does the same for privilege: it follows attached AWS-managed and customer-managed policies to their statements, since real permission usually lives there rather than inline.
- **Risk acceptance, not just detection.** An optional exception register marks specific findings as formally accepted, with a reason, owner, and expiry. Accepted findings are reported separately and do not count toward net residual risk or fail the gate until their expiry passes. That is how a real GRC program distinguishes unresolved risk from signed-off risk.

And it practices what it preaches: `--print-policy` emits the exact least-privilege, read-only IAM policy the engine itself needs to run, so the scanner is never the most over-privileged identity in the account.  [Threat-Model.md](Threat-Model.md) models the scanner's own attack surface and bounds a worst-case compromise to read-only, single-account reconnaissance.

## How it works

```
Collector  ->  Detectors  ->  Reporter  (JSON + Markdown)
                                  ^
                          Exception register
```

A collector gathers identities into a common record, detectors evaluate each record, and the reporter writes a timestamped JSON evidence report and an optional human-readable Markdown report. An exception register, if supplied, partitions findings into open and accepted. There are two collectors: `AwsCollector` reads a live account over boto3 using read-only calls, and `DemoCollector` runs offline against fixtures so the engine is reviewable without any AWS credentials.

The run exits non-zero when any HIGH or CRITICAL finding remains open (accepted exceptions do not fail the gate), which is what lets it gate a pipeline on net residual risk.

## Quickstart

Offline, no credentials needed:

```
pip install -r requirements.txt
python -m nhi_governance_engine --demo --output report.json --md-output report.md
```

With an exception register, to see accepted vs open findings:

```
python -m nhi_governance_engine --demo --exceptions examples/exceptions.example.yaml --output report.json --md-output report.md
```

Against a real account, read-only:

```
python -m nhi_governance_engine --region us-east-1 --output nhi-report.json --md-output nhi-report.md
```

See the least-privilege policy the engine needs:

```
python -m nhi_governance_engine --print-policy
```

`sample_report.json` in this repo is the output of a demo run, so you can see the evidence format without running anything.

## Tests

```
python -m pytest -q
```

The suite validates the control logic itself, missing owners, stale roles, aged keys, static credentials, wildcard and managed-policy privilege, permissive and cross-account and federated trust, unused permissions, secret rotation, Markdown rendering, and exception handling, with no AWS credentials required. The evidence engine is testable offline, and CI runs the tests on every commit.

## Phase 2: Workload Identity Federation

The worst finding the engine can raise is a long-lived static access key, so the engine's own CI does not use one. This phase runs the scan through GitHub Actions with OpenID Connect, leaving zero stored AWS keys in the repo. `oidc-federation.tf` provisions the OIDC provider and a role whose trust policy is scoped to a single repository and ref, the deliberate opposite of the wildcard-principal trust the engine flags as critical, and with the `aud` and `sub` conditions the engine's own OIDC trust-gap detector checks for. The rationale and control mapping are in `PHASE-2.md`.

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

The `assumed-role` ARN and the `AROA` user ID are an STS session, not a static-key IAM user. No AWS access key exists in the repository or in GitHub secrets; the only stored value is the role ARN, which is not sensitive. The Markdown report is published to the Actions run summary on every scan.

## Roadmap

| Item | Status |
|---|---|
| Phase 1: discovery, control mapping, CI gate | Complete |
| [Phase 2](PHASE-2.md): workload identity federation (OIDC) | Complete (live run, federated session verified) |
| Managed-policy resolution and admin detection | Complete |
| Access Advisor unused-permission detection | Complete |
| Deeper trust-policy detectors (cross-account ExternalId, OIDC aud/sub scoping) | Complete |
| Exception register with net-residual-risk gate | Complete |
| Markdown reporting and scanner threat model | Complete |
| [Enterprise scale](Enterprise-scale.md): AWS Organizations multi-account scanning | Planned |
| IAM Access Analyzer enrichment (external and unused access) | Planned |
| Managed-policy privilege-escalation patterns (PassRole chains, policy-version abuse) | Planned |
| Second platform: GitHub Actions OIDC or Entra workload identities | Planned |
| [Phase 3](PHASE-3.md): govern an AI agent as a non-human identity (Bedrock AgentCore) | Design intent |

## Layout

```
nhi_governance_engine/                        the engine package
  collectors/                                 aws (read-only boto3), demo (offline fixtures)
  detectors/                                  control logic, one module per area
  reporting/                                  json and markdown reporters
  models.py engine.py classify.py policy.py   records, runner, scoring, least-priv policy
  exceptions.py cli.py                        exception register, command line
tests/test_detectors.py                       unit tests, no AWS needed
examples/exceptions.example.yaml              sample exception register
requirements.txt                              boto3 (PyYAML for YAML registers)
oidc-federation.tf                            Phase 2 OIDC provider, role, least-priv policy
.github/workflows/nhi-governance-scan.yml     scheduled scan via OIDC, runs tests + scan
PHASE-2.md PHASE-3.md                         federation proof; AI-agent design intent
THREAT-MODEL.md                               the scanner's own threat model
sample_report.json                            example evidence output from a demo run
```
