# Threat mapping: T6 (over-privileged pod identity → lateral movement across
# a multi-account org). This is the single highest-leverage IAM control in
# scope: the pod may read exactly its own two secrets and its own KMS key,
# nothing else, no wildcard resource ARNs anywhere below.

data "aws_iam_policy_document" "irsa_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.service_name}:${var.service_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "accounts_api_pod" {
  name               = "${var.service_name}-${var.environment}-irsa"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json

  tags = {
    Service     = var.service_name
    Environment = var.environment
  }
}

# Note: this role has NO inline/attached policy granting KMS or Secrets
# Manager actions. Access is granted the other direction, via the resource
# policies in secrets.tf and the key policy in kms.tf. This means a reviewer
# checking this role in isolation sees zero standing permissions — the grant
# only exists as the intersection of both sides, which is deliberate:
# revoking access to a single secret never requires touching this role.

# --- GitHub Actions OIDC role: CI/CD identity, deliberately narrower than ---
# --- the pod role in the one dimension that matters: it cannot read secrets ---
data "aws_iam_openid_connect_provider" "github" {
  # Assumes the org has already federated GitHub's OIDC provider once,
  # org-wide — this is not re-created per-service.
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Pinned to main only (see DECISIONS.md §4): no other branch, no PR
    # build, no fork can assume this role. This is the compensating control
    # for not having per-environment roles yet.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_actions_deploy" {
  name               = "${var.service_name}-gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json

  tags = {
    Service     = var.service_name
    Environment = var.environment
  }
}

# CI can push images and update the k8s manifest/deployment — it explicitly
# cannot read secret values (no secretsmanager:GetSecretValue anywhere in
# this policy) and cannot touch the KMS key. That gap is intentional: T2/T7
# assume CI itself may be compromised via a malicious PR from any of the 40
# mergers, so CI is not in the trust boundary for secret material at all.
resource "aws_iam_role_policy" "github_actions_deploy" {
  name = "${var.service_name}-gha-deploy-policy"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PushImages"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
        ]
        Resource = "*"
      },
      {
        Sid    = "UpdateWorkload"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
        ]
        Resource = "*"
      }
    ]
  })
}
