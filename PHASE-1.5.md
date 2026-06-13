# Phase 1.5 — Federated Workload Identity

Remediation of the worst credential model the [NHI governance engine](./nhi_governance_engine.py) detects. This phase migrates a workload off long-lived static AWS access keys onto short-lived, OIDC-federated credentials, then proves the fix using the engine's own credential-model score.

## The problem

A common (bad) pattern: a CI/CD workflow stores a long-lived AWS access key as a secret and uses it on every run. The engine scores this as `STATIC_LONG_LIVED`, the bottom credential model, and it maps to OWASP NHI7 (Long-Lived Secrets). The key never rotates, it lives in CI config, and if it leaks it is valid until someone notices.

## The decision

Use GitHub Actions OIDC federation into AWS. The workflow requests a short-lived OIDC token from GitHub, and AWS STS exchanges it (`AssumeRoleWithWebIdentity`) for temporary credentials scoped to a least-privilege role. No AWS keys are stored anywhere.

The token exchange flow:

1. The workflow requests an OIDC token from GitHub (`permissions: id-token: write`).
2. `aws-actions/configure-aws-credentials` presents that token to AWS STS.
3. The role trust policy validates the token's `aud` and `sub` claims, and only then issues short-lived credentials.

The `sub` claim is scoped to one repo and one ref (see `oidc-federation.tf`), which is the deliberate opposite of the wildcard-principal trust policy the engine flags as CRITICAL.

## Files

| File | Purpose |
|---|---|
| `oidc-federation.tf` | OIDC provider, the federated role, the `sub`-scoped trust policy, and the least-privilege read-only policy (the same one the engine prints with `--print-policy`). |
| `nhi-governance-scan.yml` | The workflow, running the engine on a schedule via OIDC. Goes at `.github/workflows/`. |

## Apply

```bash
terraform init && terraform apply
# Take the nhi_scan_role_arn output and set it as a repo VARIABLE (not a secret):
#   Settings > Secrets and variables > Actions > Variables > NHI_SCAN_ROLE_ARN
```

There is no AWS access key to create, store, or rotate. That is the point.

## Proving the fix with the engine

This is the part that makes it portfolio evidence rather than a config change:

- Before: the workflow ran as the `workshop-pipeline` IAM user, backed by a long-lived
  access key. The engine scored it `STATIC_LONG_LIVED` and flagged it under NHI4.
- After: the workflow authenticates via OIDC as a short-lived assumed-role session,
  verified by `aws sts get-caller-identity` returning an `assumed-role` ARN rather than an
  IAM user. No AWS key backs the scan, and nothing is stored in the repo or GitHub secrets.

The `workshop-pipeline` user is retained in the sandbox as a deliberate `STATIC_LONG_LIVED`
example, so the engine always has a real finding to surface. In production you would delete
that key as part of offboarding.


## Controls

| Control | How this satisfies it |
|---|---|
| NIST 800-53 IA-5 (Authenticator Management) | Eliminates a long-lived static credential in favor of short-lived, automatically issued ones. |
| NIST 800-53 AC-6 (Least Privilege) | The role grants only the read-only actions the engine needs. |
| NIST 800-53 IA-9 (Service Identification) | The workload identity is federated and scoped by `sub` to a single repo and ref. |
| OWASP NHI7 (Long-Lived Secrets) | Removed for this workload entirely. |
