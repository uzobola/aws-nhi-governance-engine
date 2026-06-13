# ---------------------------------------------------------------------------
# Read-only IAM policy for the engine's own execution role
# ---------------------------------------------------------------------------

from __future__ import annotations

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

