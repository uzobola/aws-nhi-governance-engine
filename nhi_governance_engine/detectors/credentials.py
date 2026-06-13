# ---------------------------------------------------------------------------
# Detectors for stale access keys and static credential models
# -------------------------------------------------------- -------------------


from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType, CredentialModel
from ..controls import NHI_LONG_LIVED_SECRETS, NHI_INSECURE_AUTH, IA_5
from ..util import _fid


def detect_stale_access_key(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    for k in rec.access_keys:
        if k.status != "Active":
            continue
        if k.age_days is not None and k.age_days > cfg.key_max_age_days:
            yield Finding(
                finding_id=_fid(f"NHI-KEY-AGE-{k.key_id[-4:]}", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title=f"Active access key is {k.age_days} days old (no rotation)",
                severity=Severity.HIGH, owasp_nhi=NHI_LONG_LIVED_SECRETS,
                nist_800_53=IA_5,
                evidence={"key_id": k.key_id, "age_days": k.age_days,
                          "last_used_days": k.last_used_days},
                remediation="Rotate the key, or migrate the workload off static "
                            "keys to an STS-assumed role / OIDC federation.")


def detect_static_credential_model(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    if rec.credential_model == CredentialModel.STATIC_LONG_LIVED and \
            rec.nhi_type == NHIType.IAM_USER:
        yield Finding(
            finding_id=_fid("NHI-STATIC-CRED", rec), nhi_id=rec.id,
            nhi_type=rec.nhi_type.value,
            title="Workload authenticates with long-lived static credentials",
            severity=Severity.MEDIUM, owasp_nhi=NHI_INSECURE_AUTH,
            nist_800_53=IA_5,
            evidence={"credential_model": rec.credential_model.value},
            remediation="Target state is short-lived federated credentials "
                        "(IRSA / GitHub OIDC) or an assumed role, not static keys.")