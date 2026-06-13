from __future__ import annotations
import json
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from ..models import NHIRecord, NHIType, AccessKey, CredentialModel
from ..classify import classify_credential_model
from ..util import _as_list
from .base import BaseCollector

# ---------------------------------------------------------------------------
# AWS Collector
# ---------------------------------------------------------------------------



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
                managed = self._resolve_managed_policies(
                    self.iam.list_attached_role_policies(
                        RoleName=r["RoleName"]).get("AttachedPolicies", []))
                rec = NHIRecord(
                    id=r["Arn"],
                    name=r["RoleName"],
                    nhi_type=NHIType.IAM_ROLE,
                    tags=tags,
                    created_days_ago=self._days_since(r.get("CreateDate")),
                    last_used_days=self._days_since(last_used),
                    trust_policy=r.get("AssumeRolePolicyDocument"),
                    policy_statements=statements,
                    attached_managed_policies=managed,
                    service_last_accessed=self._service_last_accessed(r["Arn"]),
                )
                rec.credential_model = classify_credential_model(rec)
                out.append(rec)
        return out

    def _service_last_accessed(self, arn: str) -> List[Dict[str, Any]]:
        """IAM Access Advisor: generate + poll last-accessed details so the engine
        can flag services granted but never (or no longer) used. Bounded poll;
        skips gracefully on timeout or error rather than failing the scan.
        TODO: at scale, generate all jobs first then poll, to parallelize."""
        try:
            job = self.iam.generate_service_last_accessed_details(Arn=arn)["JobId"]
        except Exception:
            return []
        for _ in range(10):                       # bounded ~10s; jobs are usually quick
            resp = self.iam.get_service_last_accessed_details(JobId=job)
            status = resp.get("JobStatus")
            if status == "COMPLETED":
                return [{"service": s.get("ServiceNamespace"),
                         "last_authenticated_days": self._days_since(s.get("LastAuthenticated"))}
                        for s in resp.get("ServicesLastAccessed", [])]
            if status == "FAILED":
                return []
            time.sleep(1)
        return []

    def _resolve_managed_policies(self, attached: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Resolve attached managed policies (AWS-managed and customer-managed)
        to their statements via the default version. This is where real-world
        privilege usually lives, so the inline-only view misses it."""
        out: List[Dict[str, Any]] = []
        for ap in attached:
            arn = ap["PolicyArn"]
            try:
                ver = self.iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                doc = self.iam.get_policy_version(
                    PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
                statements = _as_list(doc.get("Statement", []))
            except Exception:
                statements = []
            out.append({
                "name": ap["PolicyName"],
                "arn": arn,
                "aws_managed": arn.startswith("arn:aws:iam::aws:policy/"),
                "statements": statements,
            })
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