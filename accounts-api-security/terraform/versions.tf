terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  # No apply is performed for this assessment. `terraform validate` and
  # `terraform plan` (against no live credentials, or with `-refresh=false`)
  # are the expected checks — see README.md.
}

variable "aws_region" {
  description = "AWS region accounts-api runs in"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"
}

variable "service_name" {
  type    = string
  default = "accounts-api"
}

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS cluster's OIDC provider, for IRSA trust policy. Placeholder — this cluster is not created by this repo (assessment states the service already runs on an existing shared EKS cluster)."
  type        = string
  default     = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.ap-south-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
}

variable "eks_oidc_provider_url" {
  type    = string
  default = "oidc.eks.ap-south-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
}

variable "github_repo" {
  description = "org/repo allowed to assume the CI deploy role via GitHub OIDC"
  type        = string
  default     = "example-org/accounts-api"
}

variable "rds_kms_alias" {
  type    = string
  default = "alias/accounts-api-rds"
}
