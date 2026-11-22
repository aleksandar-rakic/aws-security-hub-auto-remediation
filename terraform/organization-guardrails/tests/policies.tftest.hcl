# Plans against a mocked provider: no AWS account or credentials needed.
mock_provider "aws" {}

variables {
  target_ids            = ["ou-ab12-cdefgh34"]
  exempt_principal_arns = ["arn:aws:iam::*:role/break-glass"]
}

run "default_policies_fit_the_scp_size_limit" {
  command = plan

  assert {
    condition     = toset(keys(aws_organizations_policy.this)) == toset(["protect-security-services", "deny-root-user"])
    error_message = "Without allowed_regions only the two baseline policies are created."
  }

  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : length(p.content) <= 5120])
    error_message = "A policy exceeds the 5,120 character SCP limit."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 2
    error_message = "Each policy is attached to each target."
  }
}

run "exempt_principals_are_excluded_from_denies" {
  command = plan

  assert {
    condition = (
      jsondecode(aws_organizations_policy.this["protect-security-services"].content).Statement[0].Condition.ArnNotLike["aws:PrincipalArn"]
      == ["arn:aws:iam::*:role/break-glass"]
    )
    error_message = "Break-glass roles must be exempt from DenyDisablingDetection."
  }

  assert {
    condition = (
      !contains(keys(jsondecode(aws_organizations_policy.this["protect-security-services"].content).Statement[2]), "Condition")
    )
    error_message = "Nobody is exempt from DenyLeavingTheOrganization."
  }
}

run "no_empty_condition_without_exempt_principals" {
  command = plan

  variables {
    exempt_principal_arns = []
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_organizations_policy.this["protect-security-services"].content).Statement :
      !contains(keys(s), "Condition")
    ])
    error_message = "An empty Condition block must not be rendered."
  }
}

run "region_guardrail_is_opt_in" {
  command = plan

  variables {
    allowed_regions = ["eu-central-1", "eu-west-1"]
    target_ids      = ["ou-ab12-cdefgh34", "123456789012"]
  }

  assert {
    condition     = length(aws_organizations_policy.this["region-guardrail"].content) <= 5120
    error_message = "The region guardrail exceeds the SCP size limit."
  }

  assert {
    condition = (
      jsondecode(aws_organizations_policy.this["region-guardrail"].content).Statement[0].Condition.StringNotEquals["aws:RequestedRegion"]
      == ["eu-central-1", "eu-west-1"]
    )
    error_message = "The region guardrail must deny every region except allowed_regions."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 6
    error_message = "Three policies on two targets make six attachments."
  }
}

run "root_targets_are_rejected" {
  command = plan

  variables {
    target_ids = ["r-ab12"]
  }

  expect_failures = [var.target_ids]
}
