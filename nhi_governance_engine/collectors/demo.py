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
                service_last_accessed=[  # Access Advisor: admin grant, but only S3 is ever touched
                    {"service": "s3", "last_authenticated_days": 5},
                    {"service": "dynamodb", "last_authenticated_days": None},
                    {"service": "ec2", "last_authenticated_days": None},
                    {"service": "iam", "last_authenticated_days": 400}],
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
            NHIRecord(  # clean except: cross-account trust to a partner, no ExternalId
                id="arn:aws:iam::000000000000:role/partner-integration",
                name="partner-integration", nhi_type=NHIType.IAM_ROLE,
                tags={"Owner": "integrations@corp.com"},
                created_days_ago=120, last_used_days=3,
                trust_policy={"Statement": [{"Effect": "Allow",
                              "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                              "Action": "sts:AssumeRole"}]},
                policy_statements=[{"Effect": "Allow", "Action": ["s3:GetObject"],
                                    "Resource": "arn:aws:s3:::partner-data/*"}],
            ),
            NHIRecord(  # clean except: GitHub OIDC trust whose sub is not scoped to a repo
                id="arn:aws:iam::000000000000:role/ci-oidc-deployer",
                name="ci-oidc-deployer", nhi_type=NHIType.IAM_ROLE,
                tags={"Owner": "platform@corp.com"},
                created_days_ago=45, last_used_days=1,
                trust_policy={"Statement": [{"Effect": "Allow",
                              "Principal": {"Federated":
                                  "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
                              "Action": "sts:AssumeRoleWithWebIdentity",
                              "Condition": {
                                  "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                                  "StringLike": {"token.actions.githubusercontent.com:sub": "*"}}}]},
                policy_statements=[{"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"],
                                    "Resource": "*"}],
            ),
            NHIRecord(  # secret with rotation disabled -> long-lived secret
                id="arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-master",
                name="prod/db-master", nhi_type=NHIType.SECRET,
                tags={"Owner": "dba@corp.com"},
                created_days_ago=200, rotation_enabled=False, last_rotated_days=None),
            NHIRecord(  # clean inline + owner + recently used, but admin via a managed policy
                id="arn:aws:iam::000000000000:role/data-platform-app",
                name="data-platform-app", nhi_type=NHIType.IAM_ROLE,
                tags={"Owner": "data-team@corp.com"},
                created_days_ago=90, last_used_days=2,
                trust_policy={"Statement": [{"Effect": "Allow",
                              "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                              "Action": "sts:AssumeRole"}]},
                policy_statements=[{"Effect": "Allow", "Action": ["s3:GetObject"],
                                    "Resource": "arn:aws:s3:::data-platform/*"}],
                attached_managed_policies=[{
                    "name": "AdministratorAccess",
                    "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "aws_managed": True,
                    "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}],
            ),
        ]
        for r in recs:
            r.credential_model = classify_credential_model(r)
        return recs