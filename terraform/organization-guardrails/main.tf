terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Run from the management account (or an account delegated for AWS Organizations policies).
provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

locals {
  # Principals that may still do what the policies deny: break-glass roles and
  # the pipeline that deploys these guardrails and the remediation roles.
  exempt = length(var.exempt_principal_arns) == 0 ? {} : {
    ArnNotLike = { "aws:PrincipalArn" = var.exempt_principal_arns }
  }
  # Statement fragment: no Condition key at all when nobody is exempt.
  exempt_condition = length(local.exempt) == 0 ? {} : { Condition = local.exempt }

  protect_security_services = {
    Version = "2012-10-17"
    Statement = [
      merge({
        Sid    = "DenyDisablingDetection"
        Effect = "Deny"
        Action = [
          "access-analyzer:DeleteAnalyzer",
          "cloudtrail:DeleteTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:StopConfigurationRecorder",
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector",
          "securityhub:BatchDisableStandards",
          "securityhub:DisableSecurityHub",
          "securityhub:DisassociateFromAdministratorAccount",
          "securityhub:DisassociateFromMasterAccount",
          "securityhub:UpdateSecurityControl",
        ]
        Resource = "*"
      }, local.exempt_condition),
      merge({
        Sid    = "DenyChangingRemediationRoles"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:UpdateRole",
        ]
        Resource = [for name in var.protected_role_names : "arn:*:iam::*:role/${name}"]
      }, local.exempt_condition),
      {
        Sid      = "DenyLeavingTheOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      },
    ]
  }

  deny_root_user = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyRootUser"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { ArnLike = { "aws:PrincipalArn" = "arn:*:iam::*:root" } }
      },
    ]
  }

  # Global services are called through us-east-1 (or have no region), so they
  # are carved out of the region restriction.
  region_guardrail = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnapprovedRegions"
        Effect = "Deny"
        NotAction = [
          "a4b:*", "access-analyzer:*", "account:*", "acm:*", "aws-marketplace-management:*",
          "aws-marketplace:*", "aws-portal:*", "billing:*", "budgets:*", "ce:*", "chime:*",
          "cloudfront:*", "config:*", "cur:*", "directconnect:*", "ec2:DescribeRegions",
          "ec2:DescribeTransitGateways", "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*",
          "health:*", "iam:*", "importexport:*", "invoicing:*", "kms:*", "networkmanager:*",
          "organizations:*", "payments:*", "pricing:*", "route53-recovery-cluster:*",
          "route53-recovery-control-config:*", "route53-recovery-readiness:*", "route53:*",
          "route53domains:*", "s3:CreateMultiRegionAccessPoint", "s3:DeleteMultiRegionAccessPoint",
          "s3:DescribeMultiRegionAccessPointOperation", "s3:GetAccountPublic*",
          "s3:GetMultiRegionAccessPoint*", "s3:ListAllMyBuckets", "s3:ListMultiRegionAccessPoints",
          "s3:PutAccountPublic*", "shield:*", "sso:*", "sts:*", "support:*", "tax:*",
          "trustedadvisor:*", "waf-regional:*", "waf:*", "wafv2:*", "wellarchitected:*",
        ]
        Resource = "*"
        Condition = merge(
          { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } },
          local.exempt,
        )
      },
    ]
  }

  policies = merge(
    {
      "protect-security-services" = {
        description = "Keeps detection services on and the remediation roles intact; blocks leaving the organization"
        content     = local.protect_security_services
      }
      "deny-root-user" = {
        description = "Denies every action to member-account root users"
        content     = local.deny_root_user
      }
    },
    length(var.allowed_regions) == 0 ? {} : {
      "region-guardrail" = {
        description = "Denies regional services outside ${join(", ", var.allowed_regions)}"
        content     = local.region_guardrail
      }
    },
  )

  attachments = {
    for pair in setproduct(keys(local.policies), var.target_ids) :
    "${pair[0]}/${pair[1]}" => { policy = pair[0], target = pair[1] }
  }
}

resource "aws_organizations_policy" "this" {
  for_each = local.policies

  name        = each.key
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = jsonencode(each.value.content)
}

resource "aws_organizations_policy_attachment" "this" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.this[each.value.policy].id
  target_id = each.value.target
}
