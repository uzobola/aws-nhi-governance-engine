# ---------------------------------------------------------------------------
# Detectors for wildcard policies 
# -------------------------------------------------------- -------------------


from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType
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



def detect_overprivileged_managed_policy(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    """Flag attached managed policies that grant effective admin. This is the
    privilege the inline-only scan misses, since most real AWS permission comes
    from attached AWS-managed or customer-managed policies, not inline ones."""
    if rec.nhi_type not in (NHIType.IAM_ROLE, NHIType.IAM_USER):
        return
    for pol in rec.attached_managed_policies:
        arn = pol.get("arn", "")
        name = pol.get("name", "")
        admin = arn.endswith(":policy/AdministratorAccess") or name == "AdministratorAccess"
        if not admin:
            for stmt in pol.get("statements", []):
                if stmt.get("Effect") != "Allow":
                    continue
                if "*" in _as_list(stmt.get("Action", [])) and \
                        "*" in _as_list(stmt.get("Resource", [])):
                    admin = True
                    break
        if admin:
            yield Finding(
                finding_id=_fid(f"NHI-MANAGED-ADMIN-{name}", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title=f"Attached managed policy '{name}' grants effective admin",
                severity=Severity.HIGH, owasp_nhi=NHI_OVERPRIVILEGED,
                nist_800_53=AC_6,
                evidence={"policy_arn": arn, "aws_managed": pol.get("aws_managed")},
                remediation="Replace broad managed policies with least-privilege "
                            "policies scoped to the workload's actual actions. "
                            "TODO: confirm with Access Advisor last-accessed data.")
