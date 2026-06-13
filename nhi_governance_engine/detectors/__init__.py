# ---------------------------------------------------------------------------
# Detectors
# -------------------------------------------------------- -------------------      


from .ownership import detect_missing_owner, detect_orphaned_role
from .credentials import detect_stale_access_key, detect_static_credential_model
from .privilege import detect_wildcard_policy, detect_overprivileged_managed_policy
from .trust_policy import detect_permissive_trust_policy
from .secrets import detect_secret_no_rotation

DETECTORS = [
    detect_missing_owner,
    detect_orphaned_role,
    detect_stale_access_key,
    detect_static_credential_model,
    detect_wildcard_policy,
    detect_overprivileged_managed_policy,
    detect_permissive_trust_policy,
    detect_secret_no_rotation,
]

# TODO (next detectors to build):
#   - detect_unused_permissions: GenerateServiceLastAccessedDetails per role.
#   - detect_cross_account_trust: flag external-account principals in trust policy.
#   - detect_attached_managed_policy_wildcards: resolve + scan managed policies.
#   - detect_inactive_user_with_keys: console-less user, keys unused > N days.