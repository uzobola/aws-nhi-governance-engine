from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType
from ..controls import NHI_IMPROPER_OFFBOARDING, AC_2, AC_6
from ..util import _fid

# ---------------------------------------------------------------------------
# Ownership detectors
# ---------------------------------------------------------------------------

def detect_missing_owner(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    if rec.owner is None:
        yield Finding(
            finding_id=_fid("NHI-NO-OWNER", rec), nhi_id=rec.id,
            nhi_type=rec.nhi_type.value,
            title="Non-human identity has no accountable owner",
            severity=Severity.MEDIUM,
            owasp_nhi=NHI_IMPROPER_OFFBOARDING, nist_800_53=AC_2,
            evidence={"tags": rec.tags},
            remediation="Assign an Owner tag (team or email). Unowned NHIs are "
                        "the ones that never get reviewed or offboarded.")


def detect_orphaned_role(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    if rec.nhi_type != NHIType.IAM_ROLE:
        return
    if rec.last_used_days is None and (rec.created_days_ago or 0) > cfg.role_unused_days:
        yield Finding(
            finding_id=_fid("NHI-ROLE-NEVER-USED", rec), nhi_id=rec.id,
            nhi_type=rec.nhi_type.value,
            title="Role has never been used since creation",
            severity=Severity.MEDIUM, owasp_nhi=NHI_IMPROPER_OFFBOARDING,
            nist_800_53=f"{AC_2}; {AC_6}",
            evidence={"created_days_ago": rec.created_days_ago, "last_used_days": None},
            remediation="Confirm ownership and purpose; remove if abandoned.")
    elif rec.last_used_days is not None and rec.last_used_days > cfg.role_unused_days:
        yield Finding(
            finding_id=_fid("NHI-ROLE-STALE", rec), nhi_id=rec.id,
            nhi_type=rec.nhi_type.value,
            title=f"Role unused for {rec.last_used_days} days",
            severity=Severity.MEDIUM, owasp_nhi=NHI_IMPROPER_OFFBOARDING,
            nist_800_53=f"{AC_2}; {AC_6}",
            evidence={"last_used_days": rec.last_used_days},
            remediation="Disable, then remove after a retention window. Mirrors "
                        "your on-prem disablement-before-deletion pattern.")
