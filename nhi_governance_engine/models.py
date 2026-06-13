# ---------------------------------------------------------------------------
# 
# ---------------------------------------------------------------------------

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any




class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NHIType(str, Enum):
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    SECRET = "secret"


class CredentialModel(str, Enum):
    """How an NHI authenticates, ranked worst -> best.

    This is where the protocol/token depth starts carrying weight: the target
    state is short-lived, federated credentials, not long-lived static keys.
    Phase 3 (agent governance) extends this into issuing and constraining an
    agent's tokens (client_credentials / RFC 8693 token exchange).
    """
    STATIC_LONG_LIVED = "static_long_lived"   # IAM user access keys  (worst)
    STS_ASSUMED = "sts_assumed"               # role assumed via STS  (better)
    FEDERATED_OIDC = "federated_oidc"         # IRSA / GitHub OIDC etc (best)
    MANAGED_ROTATION = "managed_rotation"     # secret w/ rotation enabled
    UNKNOWN = "unknown"


@dataclass
class Config:
    key_max_age_days: int = 90
    key_unused_days: int = 90
    role_unused_days: int = 90
    secret_max_rotation_days: int = 90
    unused_service_days: int = 90



# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AccessKey:
    key_id: str
    age_days: Optional[int]
    last_used_days: Optional[int]
    status: str  # Active | Inactive


@dataclass
class NHIRecord:
    """Normalized representation of one non-human identity, source-agnostic so
    detectors never need to know whether it came from boto3 or a fixture."""
    id: str                                  # ARN or unique id
    name: str
    nhi_type: NHIType
    tags: Dict[str, str] = field(default_factory=dict)
    created_days_ago: Optional[int] = None
    last_used_days: Optional[int] = None     # roles: RoleLastUsed
    access_keys: List[AccessKey] = field(default_factory=list)
    trust_policy: Optional[Dict[str, Any]] = None   # roles
    policy_statements: List[Dict[str, Any]] = field(default_factory=list)
    attached_managed_policies: List[Dict[str, Any]] = field(default_factory=list)  # roles/users: resolved managed policies
    service_last_accessed: List[Dict[str, Any]] = field(default_factory=list)  # roles: IAM Access Advisor data
    rotation_enabled: Optional[bool] = None  # secrets
    last_rotated_days: Optional[int] = None  # secrets
    credential_model: CredentialModel = CredentialModel.UNKNOWN

    @property
    def owner(self) -> Optional[str]:
        for k in ("Owner", "owner", "owner_email", "OwnerEmail"):
            if self.tags.get(k):
                return self.tags[k]
        return None


@dataclass
class Finding:
    finding_id: str
    nhi_id: str
    nhi_type: str
    title: str
    severity: Severity
    owasp_nhi: str
    nist_800_53: str
    evidence: Dict[str, Any]
    remediation: str
