# ---------------------------------------------------------------------------
# Detectors for wildcard policies 
# -------------------------------------------------------- -------------------


from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity
from ..controls import NHI_OVERPRIVILEGED, AC_6
from ..util import _fid, _as_list



def detect_wildcard_policy(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    for stmt in rec.policy_statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action", []))
        resources = _as_list(stmt.get("Resource", []))
        if "*" in actions and "*" in resources:
            yield Finding(
                finding_id=_fid("NHI-WILDCARD-ADMIN", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title="Policy grants Action:* on Resource:* (effective admin)",
                severity=Severity.HIGH, owasp_nhi=NHI_OVERPRIVILEGED,
                nist_800_53=AC_6,
                evidence={"statement": stmt},
                remediation="Scope to the specific actions/resources actually "
                            "used. TODO: confirm with Access Advisor last-accessed data.")

