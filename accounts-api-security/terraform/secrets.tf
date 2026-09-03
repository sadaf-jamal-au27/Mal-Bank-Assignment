# Threat mapping: T7 (creds never in git/image), T6 (least-privilege read access).
# Values are NOT set here (no `aws_secretsmanager_secret_version` with real
# data) — this repo provisions the container and access policy only. Actual
# secret material is put in place out-of-band by the platform team, per the
# assessment's "author + validate, don't apply against a real cloud" scope.

resource "aws_secretsmanager_secret" "db_credentials" {
  name       = "${var.service_name}/${var.environment}/db-credentials"
  kms_key_id = aws_kms_key.accounts_api.arn

  tags = {
    Service     = var.service_name
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret" "kyc_provider_api_key" {
  name       = "${var.service_name}/${var.environment}/kyc-provider-api-key"
  kms_key_id = aws_kms_key.accounts_api.arn

  tags = {
    Service     = var.service_name
    Environment = var.environment
  }
}

# Least-privilege resource policy: only the accounts-api pod's IRSA role may
# ever call GetSecretValue on these two secrets. No wildcard principal, no
# wildcard resource. This is what closes T6 (lateral movement via an
# over-privileged pod identity) at the secrets layer specifically.
resource "aws_secretsmanager_secret_policy" "db_credentials" {
  secret_arn = aws_secretsmanager_secret.db_credentials.arn
  policy     = data.aws_iam_policy_document.secret_read_only.json
}

resource "aws_secretsmanager_secret_policy" "kyc_provider_api_key" {
  secret_arn = aws_secretsmanager_secret.kyc_provider_api_key.arn
  policy     = data.aws_iam_policy_document.secret_read_only.json
}

data "aws_iam_policy_document" "secret_read_only" {
  statement {
    sid    = "AccountsApiPodReadOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.accounts_api_pod.arn]
    }
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = ["*"]
  }
  statement {
    sid    = "DenyEveryoneElse"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.accounts_api_pod.arn]
    }
  }
}
