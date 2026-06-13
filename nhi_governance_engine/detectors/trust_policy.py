# ---------------------------------------------------------------------------
# Detectors for permissive trust policies
# -------------------------------------------------------- -------------------

from typing import Iterable
from ..models import NHIRecord, Config, Finding, Severity, NHIType
from ..controls import NHI_INSECURE_CLOUD_CONFIG, NHI_INSECURE_AUTH, AC_6, IA_9
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

# --- helpers for deeper trust-policy analysis ------------------------------

def _principal_accounts(principal: dict) -> list:
    """Account ids referenced by a statement's AWS principal (ARNs or bare ids)."""
    out = []
    for v in _as_list(principal.get("AWS", [])):
        if v == "*":
            continue
        if str(v).isdigit() and len(str(v)) == 12:
            out.append(str(v))
        elif ":" in str(v):
            parts = str(v).split(":")
            if len(parts) > 4 and parts[4].isdigit():
                out.append(parts[4])
    return out


def _condition_items(stmt: dict):
    """Yield (key, value) pairs across all condition operators in a statement."""
    for op_vals in stmt.get("Condition", {}).values():
        if isinstance(op_vals, dict):
            for k, v in op_vals.items():
                yield k, v


def _has_external_id(stmt: dict) -> bool:
    return any(k.lower() == "sts:externalid" for k, _ in _condition_items(stmt))


def detect_cross_account_without_externalid(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    """Cross-account trust to an external account with no sts:ExternalId is the
    classic confused-deputy gap: a third party can be induced to assume the role
    on an attacker's behalf. ExternalId is the agreed shared value that closes it."""
    if rec.nhi_type != NHIType.IAM_ROLE or not rec.trust_policy:
        return
    home = rec.id.split(":")[4] if rec.id.count(":") >= 4 else None
    for stmt in _as_list(rec.trust_policy.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        external = [a for a in _principal_accounts(principal) if a != home]
        if external and not _has_external_id(stmt):
            yield Finding(
                finding_id=_fid("NHI-TRUST-NO-EXTERNALID", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title="Cross-account trust without ExternalId (confused-deputy risk)",
                severity=Severity.HIGH, owasp_nhi=NHI_INSECURE_CLOUD_CONFIG,
                nist_800_53=f"{AC_6}; {IA_9}",
                evidence={"external_accounts": external, "trust_statement": stmt},
                remediation="Add an sts:ExternalId condition for third-party "
                            "cross-account access, or remove the external "
                            "principal if the access is not intended.")


def detect_federated_trust_gaps(rec: NHIRecord, cfg: Config) -> Iterable[Finding]:
    """OIDC / web-identity trust done loosely. Missing aud lets a token minted for
    another audience be replayed; missing or wildcarded sub lets any workload from
    that provider assume the role. For GitHub's provider, a sub not scoped to a
    repository means any repo on GitHub can assume it, the exact mistake the
    Phase 2 role is built to avoid."""
    if rec.nhi_type != NHIType.IAM_ROLE or not rec.trust_policy:
        return
    for stmt in _as_list(rec.trust_policy.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        fed = " ".join(str(x) for x in _as_list(principal.get("Federated", [])))
        if not fed or "saml-provider" in fed:        # SAML auth is out of scope here
            continue
        items = list(_condition_items(stmt))
        has_aud = any(k.lower().endswith(":aud") for k, _ in items)
        has_sub = any(k.lower().endswith(":sub") for k, _ in items)
        is_github = "token.actions.githubusercontent.com" in fed
        if not has_aud:
            yield Finding(
                finding_id=_fid("NHI-OIDC-NO-AUD", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title="OIDC trust missing audience (aud) condition",
                severity=Severity.HIGH, owasp_nhi=NHI_INSECURE_AUTH, nist_800_53=IA_9,
                evidence={"trust_statement": stmt},
                remediation="Pin the token audience with a StringEquals condition on "
                            "the provider's :aud claim (sts.amazonaws.com for GitHub).")
        if not has_sub:
            yield Finding(
                finding_id=_fid("NHI-OIDC-NO-SUB", rec), nhi_id=rec.id,
                nhi_type=rec.nhi_type.value,
                title="OIDC trust missing subject (sub) condition",
                severity=Severity.HIGH, owasp_nhi=NHI_INSECURE_AUTH, nist_800_53=IA_9,
                evidence={"trust_statement": stmt},
                remediation="Scope the trust with a condition on the provider's :sub "
                            "claim so only the intended workload can assume the role.")
        elif is_github:
            for k, v in items:
                if not k.lower().endswith(":sub"):
                    continue
                if any(val == "*" or not str(val).startswith("repo:") for val in _as_list(v)):
                    yield Finding(
                        finding_id=_fid("NHI-GH-OIDC-UNSCOPED", rec), nhi_id=rec.id,
                        nhi_type=rec.nhi_type.value,
                        title="GitHub OIDC trust sub not scoped to a repository",
                        severity=Severity.HIGH, owasp_nhi=NHI_INSECURE_CLOUD_CONFIG,
                        nist_800_53=IA_9,
                        evidence={"sub": v, "trust_statement": stmt},
                        remediation="Scope sub to repo:OWNER/REPO:ref:refs/heads/BRANCH "
                                    "(or :environment:NAME) so only your repo and ref "
                                    "can assume the role.")
                    break
