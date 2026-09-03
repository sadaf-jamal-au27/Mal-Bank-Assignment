# Customer-managed KMS key for accounts-api's secrets and RDS storage.
# Threat mapping: T7 (credentials at rest), T9 (unencrypted storage via IaC drift).
# Compensating for: relying on the default AWS-managed key, which cannot be
# scoped to a single service's IAM principals or have its own rotation/audit trail.

resource "aws_kms_key" "accounts_api" {
  description             = "CMK for ${var.service_name} secrets and RDS storage (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = data.aws_iam_policy_document.kms_key_policy.json

  tags = {
    Service     = var.service_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_kms_alias" "accounts_api" {
  name          = var.rds_kms_alias
  target_key_id = aws_kms_key.accounts_api.key_id
}

data "aws_caller_identity" "current" {}

# Key policy: root account retains admin (required by AWS), the accounts-api
# IRSA role may only Decrypt/GenerateDataKey (never manage the key), and the
# CI/deploy role has no grants on this key at all — CI never needs to read
# secret material, only to reference the ARN in a manifest.
data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid    = "RootAccountFullAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AccountsApiPodDecryptOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.accounts_api_pod.arn]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }
}
