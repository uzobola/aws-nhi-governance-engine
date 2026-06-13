# ---------------------------------------------------------------------------
# Detectors
# -------------------------------------------------------- -------------------      


from .ownership import detect_missing_owner, detect_orphaned_role
from .credentials import detect_stale_access_key, detect_static_credential_model
from .privilege import (detect_wildcard_policy, detect_overprivileged_managed_policy,
                        detect_unused_permissions)
from .trust_policy import (detect_permissive_trust_policy,
                           detect_cross_account_without_externalid,
                           detect_federated_trust_gaps)
from .secrets import detect_secret_no_rotation

DETECTORS = [
    detect_missing_owner,
    detect_orphaned_role,
    detect_stale_access_key,
    detect_static_credential_model,
    detect_wildcard_policy,
    detect_overprivileged_managed_policy,
    detect_unused_permissions,
    detect_permissive_trust_policy,
    detect_cross_account_without_externalid,
    detect_federated_trust_gaps,
    detect_secret_no_rotation,
]

# TODO (next detectors to build):
#   - detect_inactive_user_with_keys: console-less user, keys unused > N days.