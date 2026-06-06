#!/usr/bin/env python3
"""
Cloud NHI Governance Engine  (Phase 1 skeleton)
================================================

The cloud sibling of `iam_evidence_validator.py` from the on-prem
enterprise-iam-lifecycle-automation repo. Where that tool found ONE unmanaged
service account by hand in LDAP, this one discovers, scores, and governs the
non-human identity (NHI) population of an AWS account in code, and emits
control-mapped evidence.

Scope (Phase 1, deliberately bounded):
  - One AWS account.
  - Three NHI classes: IAM roles, IAM users + access keys, Secrets Manager secrets.
  - READ-ONLY analysis. No remediation. The engine runs under a read-only,
    least-privilege role (see --print-policy) so the tool practices the
    governance it preaches.

Architecture (collection is separated from analysis so detectors are testable
without AWS):
  Collector  -> List[NHIRecord]   (AwsCollector via boto3, or DemoCollector)
  Detectors  -> List[Finding]     (pure functions over NHIRecord)
  Reporter   -> JSON evidence report (severity, OWASP NHI risk, 800-53 control)

Run the offline demo (no AWS creds needed):
  python3 nhi_governance_engine.py --demo --output report.json

Run against a real account (read-only):
  python3 nhi_governance_engine.py --profile myprofile --region us-east-1 \
      --output report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Optional, Dict, Any


# ---------------------------------------------------------------------------
# Enums and config
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Control catalog  (OWASP NHI Top 10 + NIST 800-53 AC/IA)
# ---------------------------------------------------------------------------
# NOTE: OWASP NHI numbers below reflect the OWASP Non-Human Identities Top 10
# (2025). Verify against the current published list before you cite it in an
# interview or report; the names are the durable part, the numbering can shift.

NHI_IMPROPER_OFFBOARDING = "OWASP NHI1: Improper Offboarding"
NHI_INSECURE_AUTH = "OWASP NHI4: Insecure Authentication"
NHI_OVERPRIVILEGED = "OWASP NHI5: Overprivileged NHI"
NHI_INSECURE_CLOUD_CONFIG = "OWASP NHI6: Insecure Cloud Deployment Config"
NHI_LONG_LIVED_SECRETS = "OWASP NHI7: Long-Lived Secrets"

AC_2 = "NIST 800-53 AC-2 (Account Management)"
AC_6 = "NIST 800-53 AC-6 (Least Privilege)"
IA_5 = "NIST 800-53 IA-5 (Authenticator Management)"
IA_9 = "NIST 800-53 IA-9 (Service Identification and Authentication)"


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


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

class BaseCollector:
    def collect(self) -> List[NHIRecord]:
        raise NotImplementedError

    def account_id(self) -> str:
        return "unknown"


class AwsCollector(BaseCollector):
    """Real, read-only enumeration via boto3. Imports boto3 lazily so the demo
    path runs with no dependency installed."""

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None):
        import boto3  # lazy
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = self.session.client("iam")
        self.sm = self.session.client("secretsmanager")
        self.sts = self.session.client("sts")

    def account_id(self) -> str:
        return self.sts.get_caller_identity()["Account"]

    @staticmethod
    def _days_since(dt: Optional[datetime]) -> Optional[int]:
        if not dt:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days

    def collect(self) -> List[NHIRecord]:
        records: List[NHIRecord] = []
        records.extend(self._collect_roles())
        records.extend(self._collect_users())
        records.extend(self._collect_secrets())
        return records

    def _collect_roles(self) -> List[NHIRecord]:
        out: List[NHIRecord] = []
        for page in self.iam.get_paginator("list_roles").paginate():
            for r in page["Roles"]:
                # Skip AWS service-linked roles in Phase 1 (they are AWS-managed).
                if "/aws-service-role/" in r["Path"]:
                    continue
                last_used = r.get("RoleLastUsed", {}).get("LastUsedDate")
                tags = {t["Key"]: t["Value"]
                        for t in self.iam.list_role_tags(RoleName=r["RoleName"]).get("Tags", [])}
                statements = self._inline_role_statements(r["RoleName"])
                rec = NHIRecord(
                    id=r["Arn"],
                    name=r["RoleName"],
                    nhi_type=NHIType.IAM_ROLE,
                    tags=tags,
                    created_days_ago=self._days_since(r.get("CreateDate")),
                    last_used_days=self._days_since(last_used),
                    trust_policy=r.get("AssumeRolePolicyDocument"),
                    policy_statements=statements,
                )
                rec.credential_model = classify_credential_model(rec)
                out.append(rec)
        return out

    def _inline_role_statements(self, role_name: str) -> List[Dict[str, Any]]:
        # Phase 1: inline policies only. TODO: resolve attached managed policies
        # and use iam:GenerateServiceLastAccessedDetails for unused-permission
        # analysis (deeper least-privilege scoring).
        statements: List[Dict[str, Any]] = []
        for name in self.iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            statements.extend(_as_list(doc.get("Statement", [])))
        return statements

    def _collect_users(self) -> List[NHIRecord]:
        out: List[NHIRecord] = []
        for page in self.iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                keys: List[AccessKey] = []
                for k in self.iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []):
                    last_used = self.iam.get_access_key_last_used(
                        AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    keys.append(AccessKey(
                        key_id=k["AccessKeyId"],
                        age_days=self._days_since(k.get("CreateDate")),
                        last_used_days=self._days_since(last_used),
                        status=k.get("Status", "Unknown"),
                    ))
                tags = {t["Key"]: t["Value"]
                        for t in self.iam.list_user_tags(UserName=u["UserName"]).get("Tags", [])}
                rec = NHIRecord(
                    id=u["Arn"],
                    name=u["UserName"],
                    nhi_type=NHIType.IAM_USER,
                    tags=tags,
                    created_days_ago=self._days_since(u.get("CreateDate")),
                    access_keys=keys,
                )
                rec.credential_model = classify_credential_model(rec)
                out.append(rec)
        return out

    def _collect_secrets(self) -> List[NHIRecord]:
        out: List[NHIRecord] = []
        for page in self.sm.get_paginator("list_secrets").paginate():
            for s in page.get("SecretList", []):
                tags = {t["Key"]: t["Value"] for t in s.get("Tags", [])}
                rec = NHIRecord(
                    id=s["ARN"],
                    name=s["Name"],
                    nhi_type=NHIType.SECRET,
                    tags=tags,
                    created_days_ago=self._days_since(s.get("CreatedDate")),
                    last_rotated_days=self._days_since(s.get("LastRotatedDate")),
                    rotation_enabled=s.get("RotationEnabled", False),
                )
                rec.credential_model = classify_credential_model(rec)
                out.append(rec)
        return out


class DemoCollector(BaseCollector):
    """Hardcoded fixtures so the detector + reporting pipeline is runnable and
    testable with zero AWS dependency. Mirrors the kinds of findings you saw in
    Phase 5 of the on-prem repo, now at cloud scale."""

    def account_id(self) -> str:
        return "000000000000"

    def collect(self) -> List[NHIRecord]:
        recs = [
            NHIRecord(  # over-privileged, never used, no owner -> the messy one
                id="arn:aws:iam::000000000000:role/legacy-etl-runner",
                name="legacy-etl-runner", nhi_type=NHIType.IAM_ROLE,
                tags={}, created_days_ago=540, last_used_days=410,
                trust_policy={"Statement": [{"Effect": "Allow",
                              "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
                policy_statements=[{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            ),
            NHIRecord(  # IAM user with an old static key -> credential hygiene
                id="arn:aws:iam::000000000000:user/ci-deploy",
                name="ci-deploy", nhi_type=NHIType.IAM_USER,
                tags={"Owner": "platform-team@corp.com"},
                created_days_ago=300,
                access_keys=[AccessKey(key_id="AKIA...OLD", age_days=420,
                             last_used_days=12, status="Active")],
            ),
            NHIRecord(  # healthy STS-assumed workload role -> should pass clean
                id="arn:aws:iam::000000000000:role/lambda-orders-exec",
                name="lambda-orders-exec", nhi_type=NHIType.IAM_ROLE,
                tags={"Owner": "orders-team@corp.com"},
                created_days_ago=60, last_used_days=1,
                trust_policy={"Statement": [{"Effect": "Allow",
                              "Principal": {"Service": "lambda.amazonaws.com"},
                              "Action": "sts:AssumeRole"}]},
                policy_statements=[{"Effect": "Allow", "Action": ["dynamodb:GetItem"],
                                    "Resource": "arn:aws:dynamodb:*:*:table/orders"}],
            ),
            NHIRecord(  # secret with rotation disabled -> long-lived secret
                id="arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-master",
                name="prod/db-master", nhi_type=NHIType.SECRET,
                tags={"Owner": "dba@corp.com"},
                created_days_ago=200, rotation_enabled=False, last_rotated_days=None),
        ]
        for r in recs:
            r.credential_model = classify_credential_model(r)
        return recs


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else [x]


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


# ---------------------------------------------------------------------------
# Detectors  (pure functions: NHIRecord + Config -> findings)
# ---------------------------------------------------------------------------

def _fid(prefix: str, rec: NHIRecord) -> str:
    return f"{prefix}:{rec.name}"


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


# TODO (next detectors to build):
#   - detect_unused_permissions: GenerateServiceLastAccessedDetails per role.
#   - detect_cross_account_trust: flag external-account principals in trust policy.
#   - detect_attached_managed_policy_wildcards: resolve + scan managed policies.
#   - detect_inactive_user_with_keys: console-less user, keys unused > N days.

DETECTORS = [
    detect_missing_owner,
    detect_orphaned_role,
    detect_stale_access_key,
    detect_static_credential_model,
    detect_wildcard_policy,
    detect_permissive_trust_policy,
    detect_secret_no_rotation,
]


# ---------------------------------------------------------------------------
# Engine + reporter
# ---------------------------------------------------------------------------

def run_detectors(records: List[NHIRecord], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    for rec in records:
        for detector in DETECTORS:
            findings.extend(detector(rec, cfg))
    return findings


def build_report(records: List[NHIRecord], findings: List[Finding],
                 account_id: str) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity.value] += 1
    by_type: Dict[str, int] = {t.value: 0 for t in NHIType}
    for r in records:
        by_type[r.nhi_type.value] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "scope": "iam_roles, iam_users+keys, secretsmanager_secrets (read-only)",
        "summary": {
            "nhi_total": len(records),
            "nhi_by_type": by_type,
            "findings_total": len(findings),
            "findings_by_severity": by_sev,
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d


# ---------------------------------------------------------------------------
# Read-only IAM policy for the engine's own execution role
# ---------------------------------------------------------------------------

READONLY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "NhiGovernanceReadOnly",
        "Effect": "Allow",
        "Action": [
            "iam:ListRoles", "iam:ListRoleTags", "iam:ListRolePolicies",
            "iam:GetRolePolicy", "iam:ListUsers", "iam:ListUserTags",
            "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
            "iam:GenerateServiceLastAccessedDetails",
            "iam:GetServiceLastAccessedDetails",
            "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
            "sts:GetCallerIdentity",
        ],
        "Resource": "*",
    }],
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cloud NHI Governance Engine (Phase 1)")
    p.add_argument("--demo", action="store_true", help="run offline against fixtures")
    p.add_argument("--profile", help="AWS profile name")
    p.add_argument("--region", help="AWS region")
    p.add_argument("--output", default="-", help="output JSON path ('-' = stdout)")
    p.add_argument("--print-policy", action="store_true",
                   help="print the read-only IAM policy the engine needs and exit")
    args = p.parse_args(argv)

    if args.print_policy:
        print(json.dumps(READONLY_POLICY, indent=2))
        return 0

    cfg = Config()
    collector: BaseCollector = DemoCollector() if args.demo else \
        AwsCollector(profile=args.profile, region=args.region)

    records = collector.collect()
    findings = run_detectors(records, cfg)
    report = build_report(records, findings, collector.account_id())

    out = json.dumps(report, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w") as fh:
            fh.write(out)
        print(f"Wrote {len(findings)} findings across {len(records)} NHIs "
              f"-> {args.output}", file=sys.stderr)

    # Non-zero exit if anything HIGH/CRITICAL, so this can gate a pipeline later.
    severe = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
    return 1 if severe else 0


if __name__ == "__main__":
    raise SystemExit(main())
