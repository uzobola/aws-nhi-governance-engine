from __future__ import annotations
from ..models import NHIRecord, NHIType, AccessKey
from ..classify import classify_credential_model
from .base import BaseCollector

# ---------------------------------------------------------------------------
# Demo Collector
# ---------------------------------------------------------------------------

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