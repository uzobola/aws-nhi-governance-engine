# ---------------------------------------------------------------------------   
# Detectors for unrotated secrets
# -------------------------------------------------------- -------------------


from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType
from ..controls import NHI_LONG_LIVED_SECRETS, IA_5
from ..util import _fid

def detect_secret_no_rotation(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    if rec.nhi_type != NHIType.SECRET:
        return
    if rec.rotation_enabled is False:
        yield Finding(
            finding_id=_fid("NHI-SECRET-NO-ROTATION", rec), nhi_id=rec.id,
            nhi_type=rec.nhi_type.value,
            title="Secret has rotation disabled",
            severity=Severity.MEDIUM, owasp_nhi=NHI_LONG_LIVED_SECRETS,
            nist_800_53=IA_5,
            evidence={"rotation_enabled": rec.rotation_enabled,
                      "last_rotated_days": rec.last_rotated_days},
            remediation="Enable automatic rotation with an appropriate interval.")