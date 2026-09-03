# AWS idiom mapping for the registry: this repo's actual pipeline pushes to
# ghcr.io (free, OIDC-native, no billing account needed — see README.md's
# mapping table). This resource documents what the equivalent AWS-side
# control looks like, since ECR has a hard registry-level immutability
# guarantee that ghcr.io does not — see docs/DECISIONS.md "Section 2" for
# how tag mutation is actually prevented on the registry this repo uses.
resource "aws_ecr_repository" "accounts_api" {
  name                 = var.service_name
  image_tag_mutability = "IMMUTABLE" # registry itself rejects any push that reuses an existing tag

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.accounts_api.arn
  }

  tags = {
    Service     = var.service_name
    Environment = var.environment
  }
}

# Lifecycle policy: keep the last N SHA-tagged images so immutability doesn't
# mean unbounded storage growth; nothing here allows overwriting a tag,
# only expiring old ones after they age out.
resource "aws_ecr_lifecycle_policy" "accounts_api" {
  repository = aws_ecr_repository.accounts_api.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 14
      }
      action = { type = "expire" }
    }]
  })
}
