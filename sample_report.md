# NHI Governance Report

**Account:** 000000000000  
**Generated:** 2026-06-14T04:20:58.608972+00:00  
**Scope:** iam_roles, iam_users+keys, secretsmanager_secrets (read-only)

## Summary

- NHIs scanned: **7** (iam_role: 5, iam_user: 1, secret: 1)
- Findings: **11** (open: 10, accepted: 1)
- Net residual risk: CRITICAL 1, HIGH 5, MEDIUM 4, LOW 0, INFO 0

## Open findings

### CRITICAL (1)

**Role trust policy allows any principal to assume it** -- `legacy-etl-runner`  
NHI6:2025 Insecure Cloud Deployment Configurations · NIST 800-53 AC-6 (Least Privilege); NIST 800-53 IA-9 (Service Identification and Authentication)  
Evidence: trust_statement = {...}  
Remediation: Restrict the trust policy to specific, intended principals. This is the cross-account assumption risk your STS/AssumeRole detection pipeline watches for.

### HIGH (5)

**Policy grants Action:* on Resource:* (effective admin)** -- `legacy-etl-runner`  
NHI5:2025 Overprivileged NHI · NIST 800-53 AC-6 (Least Privilege)  
Evidence: statement = {...}  
Remediation: Scope to the specific actions/resources actually used. TODO: confirm with Access Advisor last-accessed data.

**Active access key is 420 days old (no rotation)** -- `ci-deploy`  
NHI7:2025 Long-Lived Secrets · NIST 800-53 IA-5 (Authenticator Management)  
Evidence: key_id = AKIA...OLD; age_days = 420; last_used_days = 12  
Remediation: Rotate the key, or migrate the workload off static keys to an STS-assumed role / OIDC federation.

**Cross-account trust without ExternalId (confused-deputy risk)** -- `partner-integration`  
NHI6:2025 Insecure Cloud Deployment Configurations · NIST 800-53 AC-6 (Least Privilege); NIST 800-53 IA-9 (Service Identification and Authentication)  
Evidence: external_accounts = 999988887777; trust_statement = {...}  
Remediation: Add an sts:ExternalId condition for third-party cross-account access, or remove the external principal if the access is not intended.

**GitHub OIDC trust sub not scoped to a repository** -- `ci-oidc-deployer`  
NHI6:2025 Insecure Cloud Deployment Configurations · NIST 800-53 IA-9 (Service Identification and Authentication)  
Evidence: sub = *; trust_statement = {...}  
Remediation: Scope sub to repo:OWNER/REPO:ref:refs/heads/BRANCH (or :environment:NAME) so only your repo and ref can assume the role.

**Attached managed policy 'AdministratorAccess' grants effective admin** -- `data-platform-app`  
NHI5:2025 Overprivileged NHI · NIST 800-53 AC-6 (Least Privilege)  
Evidence: policy_arn = arn:aws:iam::aws:policy/AdministratorAccess; aws_managed = True  
Remediation: Replace broad managed policies with least-privilege policies scoped to the workload's actual actions. TODO: confirm with Access Advisor last-accessed data.

### MEDIUM (4)

**Non-human identity has no accountable owner** -- `legacy-etl-runner`  
NHI1:2025 Improper Offboarding · NIST 800-53 AC-2 (Account Management)  
Evidence: tags = {...}  
Remediation: Assign an Owner tag (team or email). Unowned NHIs are the ones that never get reviewed or offboarded.

**Role unused for 410 days** -- `legacy-etl-runner`  
NHI1:2025 Improper Offboarding · NIST 800-53 AC-2 (Account Management); NIST 800-53 AC-6 (Least Privilege)  
Evidence: last_used_days = 410  
Remediation: Disable, then remove after a retention window. Mirrors your on-prem disablement-before-deletion pattern.

**3 granted service(s) unused per Access Advisor** -- `legacy-etl-runner`  
NHI5:2025 Overprivileged NHI · NIST 800-53 AC-6 (Least Privilege)  
Evidence: unused_services = dynamodb, ec2, iam; window_days = 90; detail = [...]  
Remediation: Remove permissions for services the role does not use. Last-accessed data is the evidence for right-sizing the policy to least privilege.

**Secret has rotation disabled** -- `db-master`  
NHI7:2025 Long-Lived Secrets · NIST 800-53 IA-5 (Authenticator Management)  
Evidence: rotation_enabled = False; last_rotated_days = None  
Remediation: Enable automatic rotation with an appropriate interval.

## Accepted exceptions (1)

**Workload authenticates with long-lived static credentials** -- `ci-deploy`  
NHI4:2025 Insecure Authentication · NIST 800-53 IA-5 (Authenticator Management)  
Accepted by platform@corp.com, expires 2026-12-31 -- Legacy CI runner; OIDC migration tracked in JIRA-1234

