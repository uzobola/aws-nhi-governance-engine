
"""
Cloud NHI Governance Engine
===========================

The cloud sibling of `iam_evidence_validator.py` from the on-prem
enterprise-iam-lifecycle-automation repo. Where that tool found ONE unmanaged
service account by hand in LDAP, this one discovers, scores, and governs the
non-human identity (NHI) population of an AWS account in code, and emits
control-mapped evidence.

Scope:
  - One AWS account.
  - Three NHI classes: IAM roles, IAM users + access keys, Secrets Manager secrets.
  - READ-ONLY analysis. No remediation. The engine runs under a read-only,
    least-privilege role (see --print-policy) so the tool practices the
    governance it preaches.

Architecture (collection separated from analysis so detectors are testable
without AWS):
  Collector  -> List[NHIRecord]   (AwsCollector via boto3, or DemoCollector)
  Detectors  -> List[Finding]     (pure functions over NHIRecord)
  Reporter   -> JSON evidence report (severity, OWASP NHI risk, 800-53 control)

Offline demo (no AWS creds needed):
  python -m nhi_governance_engine --demo --output report.json

Against a real account (read-only):
  python -m nhi_governance_engine --profile myprofile --region us-east-1 --output report.json
"""


from .models import (
    Severity, NHIType, CredentialModel, Config, AccessKey, NHIRecord, Finding,
)
from .classify import classify_credential_model
from .detectors import (
    DETECTORS,
    detect_missing_owner, detect_orphaned_role, detect_stale_access_key,
    detect_static_credential_model, detect_wildcard_policy,
    detect_overprivileged_managed_policy,
    detect_permissive_trust_policy, detect_secret_no_rotation,
)


from .engine import run_detectors

from .models import (
    Severity, NHIType, CredentialModel, Config, AccessKey, NHIRecord, Finding,
)
from .classify import classify_credential_model
from .detectors import (
    DETECTORS,
    detect_missing_owner, detect_orphaned_role, detect_stale_access_key,
    detect_static_credential_model, detect_wildcard_policy,
    detect_overprivileged_managed_policy,
    detect_permissive_trust_policy, detect_secret_no_rotation,
)
from .engine import run_detectors