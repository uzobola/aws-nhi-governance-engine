from __future__ import annotations
import json
from .models import NHIRecord, NHIType, CredentialModel


# ---------------------------------------------------------------------------
# Credential / token model scoring
# ---------------------------------------------------------------------------

def classify_credential_model(rec: NHIRecord) -> CredentialModel:
    if rec.nhi_type == NHIType.IAM_USER and rec.access_keys:
        return CredentialModel.STATIC_LONG_LIVED
    if rec.nhi_type == NHIType.SECRET:
        return (CredentialModel.MANAGED_ROTATION if rec.rotation_enabled
                else CredentialModel.STATIC_LONG_LIVED)
    if rec.nhi_type == NHIType.IAM_ROLE and rec.trust_policy:
        principals = json.dumps(rec.trust_policy)
        if "oidc-provider" in principals or "OpenIDConnect" in principals:
            return CredentialModel.FEDERATED_OIDC
        if "Service" in principals or "sts:AssumeRole" in principals:
            return CredentialModel.STS_ASSUMED
    return CredentialModel.UNKNOWN

