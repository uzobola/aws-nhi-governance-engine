# =============================================================================
# Phase 1.5 - Federated Workload Identity (GitHub Actions OIDC -> AWS)
# =============================================================================
# Replaces long-lived static AWS access keys (the worst credential model your
# NHI engine flags) with short-lived, federated credentials. No secrets stored
# in GitHub. The workload (the NHI engine's own scheduled scan) authenticates
# by exchanging a GitHub-issued OIDC token for temporary STS credentials.
#
# Controls satisfied: NIST 800-53 IA-5 (authenticator management), AC-6 (least
# privilege). Eliminates OWASP NHI7 (Long-Lived Secrets) for this workload.
# =============================================================================

variable "github_repo" {
  description = "owner/repo allowed to assume the role"
  type        = string
  default     = "uzobola/aws-nhi-governance-engine"
}

variable "github_ref" {
  description = "git ref allowed to assume the role (branch or environment)"
  type        = string
  default     = "ref:refs/heads/main"
}

# Fetch GitHub's OIDC thumbprint dynamically instead of hardcoding a value that
# can go stale.
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

# Role assumable ONLY by the specified repo + ref via web identity.
resource "aws_iam_role" "github_actions_nhi_scan" {
  name = "github-actions-nhi-scan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        # Audience must be the AWS STS audience.
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # Subject scopes the trust to one repo and one ref. This is the
        # deliberate opposite of the wildcard-principal trust policy your
        # engine flags as CRITICAL.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:${var.github_ref}"
        }
      }
    }]
  })
}

# Least privilege: exactly the read-only access the NHI engine needs, no more.
# This is the same policy the engine prints with --print-policy.
resource "aws_iam_role_policy" "nhi_scan_readonly" {
  name = "nhi-governance-readonly"
  role = aws_iam_role.github_actions_nhi_scan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "NhiGovernanceReadOnly"
      Effect = "Allow"
      Action = [
        "iam:ListRoles", "iam:ListRoleTags", "iam:ListRolePolicies", "iam:GetRolePolicy",
        "iam:ListUsers", "iam:ListUserTags", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
        "iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "sts:GetCallerIdentity"
      ]
      Resource = "*"
    }]
  })
}

output "nhi_scan_role_arn" {
  description = "Set this as the GitHub Actions variable NHI_SCAN_ROLE_ARN (not a secret)."
  value       = aws_iam_role.github_actions_nhi_scan.arn
}
