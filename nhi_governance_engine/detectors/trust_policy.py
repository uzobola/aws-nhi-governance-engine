# ---------------------------------------------------------------------------
# Detectors for permissive trust policies
# -------------------------------------------------------- -------------------

from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType
from ..controls import NHI_INSECURE_CLOUD_CONFIG, AC_6, IA_9
from ..util import _fid, _as_list

def detect_permissive_trust_policy(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    if rec.nhi_type != NHIType.IAM_ROLE or not rec.trust_policy:
        return
    for stmt in _as_list(rec.trust_policy.get("Statement", [])):
        principal = stmt.get("Principal", {})
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            yield Finding(
                finding_id=_fid("NHI-TRUST-WILDCARD", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title="Role trust policy allows any principal to assume it",
                severity=Severity.CRITICAL, owasp_nhi=NHI_INSECURE_CLOUD_CONFIG,
                nist_800_53=f"{AC_6}; {IA_9}",
                evidence={"trust_statement": stmt},
                remediation="Restrict the trust policy to specific, intended "
                            "principals. This is the cross-account assumption risk "
                            "your STS/AssumeRole detection pipeline watches for.")