terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_iam_user" "cspm_scanner" {
  name = "cspm-scanner-readonly"
  tags = {
    Project     = "CSPM Scanner"
    Environment = "security-tooling"
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_user_policy_attachment" "security_audit" {
  user       = aws_iam_user.cspm_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_access_key" "cspm_scanner_key" {
  user = aws_iam_user.cspm_scanner.name
}
