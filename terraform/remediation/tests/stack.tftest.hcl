# Plans against a mocked AWS provider; the archive provider runs for real and
# packages ../../remediator/src.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  region = "eu-central-1"
}

run "safe_defaults" {
  command = plan

  assert {
    condition     = aws_lambda_function.remediator.environment[0].variables.DRY_RUN == "true"
    error_message = "A fresh deployment must start in dry run."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty) == 0
    error_message = "The GuardDuty quarantine rule must not exist unless quarantine is enabled."
  }

  assert {
    condition     = keys(aws_lambda_permission.events) == ["controls"]
    error_message = "Only the controls rule may invoke the Lambda by default."
  }
}

run "rule_matches_only_new_failed_findings_for_selected_controls" {
  command = plan

  variables {
    controls = ["S3.8", "EC2.13"]
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.controls.event_pattern).detail.findings.Compliance.SecurityControlId
      == ["S3.8", "EC2.13"]
    )
    error_message = "The rule must match exactly the selected controls."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.controls.event_pattern).detail.findings.Workflow.Status == ["NEW"]
      && jsondecode(aws_cloudwatch_event_rule.controls.event_pattern).detail.findings.Compliance.Status == ["FAILED"]
    )
    error_message = "Only NEW, FAILED findings may trigger remediation, or updates would loop."
  }
}

run "quarantine_adds_its_own_rule" {
  command = plan

  variables {
    quarantine_enabled = true
    dry_run            = false
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.guardduty[0].event_pattern).detail.findings.Severity.Label
      == ["HIGH", "CRITICAL"]
    )
    error_message = "Quarantine must react only to HIGH and CRITICAL GuardDuty findings."
  }

  assert {
    condition     = toset(keys(aws_cloudwatch_event_target.remediator)) == toset(["controls", "guardduty"])
    error_message = "Both rules must target the Lambda."
  }
}

run "unsupported_controls_are_rejected" {
  command = plan

  variables {
    controls = ["S3.8", "IAM.1"]
  }

  expect_failures = [var.controls]
}
