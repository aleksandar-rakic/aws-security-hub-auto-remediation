terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Deploy once per member account (from your account-vending pipeline or with
# a provider per account). IAM is global, so the region only affects the API
# endpoint used.
provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

variable "region" {
  description = "Any region; IAM is global."
  type        = string
  default     = "us-east-1"
}

variable "role_name" {
  description = "Must equal member_role_name of the remediation stack."
  type        = string
  default     = "security-hub-remediation-member"
}

variable "remediator_role_arn" {
  description = "role_arn output of ../remediation: the only principal allowed to assume this role."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", var.remediator_role_arn))
    error_message = "remediator_role_arn must be an IAM role ARN."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    project = "security-hub-auto-remediation"
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.remediator_role_arn]
    }
  }
}

resource "aws_iam_role" "member" {
  name                 = var.role_name
  description          = "Assumed by the Security Hub remediation Lambda to fix findings in this account"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "remediation" {
  name   = "remediation"
  role   = aws_iam_role.member.id
  policy = file("${path.module}/../policies/remediation-permissions.json")
}

output "role_arn" {
  description = "ARN of the member role."
  value       = aws_iam_role.member.arn
}
