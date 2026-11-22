data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Matches findings once, when Security Hub imports them as NEW. The Lambda
  # moves each finding to RESOLVED or NOTIFIED, so updates do not re-trigger it.
  control_pattern = {
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          Status            = ["FAILED"]
          SecurityControlId = local.controls
        }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  }

  guardduty_pattern = {
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        ProductName = ["GuardDuty"]
        Severity    = { Label = ["HIGH", "CRITICAL"] }
        Resources   = { Type = ["AwsEc2Instance"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  }

  rules = merge(
    { controls = aws_cloudwatch_event_rule.controls },
    var.quarantine_enabled ? { guardduty = aws_cloudwatch_event_rule.guardduty[0] } : {},
  )
}

data "archive_file" "remediator" {
  type        = "zip"
  source_dir  = "${path.module}/../../remediator/src"
  output_path = "${path.module}/.build/remediator.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "remediator" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "remediator" {
  function_name = var.name
  description   = "Remediates selected Security Hub findings and records the outcome on each finding"
  role          = aws_iam_role.remediator.arn

  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "remediator.handler.lambda_handler"
  filename         = data.archive_file.remediator.output_path
  source_code_hash = data.archive_file.remediator.output_base64sha256

  timeout                        = 120
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrency

  environment {
    variables = {
      DRY_RUN             = tostring(var.dry_run)
      QUARANTINE_ENABLED  = tostring(var.quarantine_enabled)
      MEMBER_ROLE_NAME    = var.member_role_name
      EXEMPTION_TAG_KEY   = var.exemption_tag.key
      EXEMPTION_TAG_VALUE = var.exemption_tag.value
    }
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.remediator.name
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_iam_role_policy.remediator]
}

# Failed invocations are retried twice by Lambda, then land in the DLQ with
# the original event, ready for a redrive once the cause is fixed.
resource "aws_lambda_function_event_invoke_config" "remediator" {
  function_name                = aws_lambda_function.remediator.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "EventBridgeDeliveryFailures"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for rule in local.rules : rule.arn]
    }
  }

  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

resource "aws_cloudwatch_event_rule" "controls" {
  name          = "${var.name}-controls"
  description   = "New failed findings for the controls handled by ${var.name}"
  event_pattern = jsonencode(local.control_pattern)
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  count = var.quarantine_enabled ? 1 : 0

  name          = "${var.name}-guardduty-ec2"
  description   = "New HIGH and CRITICAL GuardDuty findings about EC2 instances"
  event_pattern = jsonencode(local.guardduty_pattern)
}

resource "aws_cloudwatch_event_target" "remediator" {
  for_each = local.rules

  rule = each.value.name
  arn  = aws_lambda_function.remediator.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 10
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  for_each = local.rules

  statement_id   = "events-${each.key}"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.remediator.function_name
  principal      = "events.amazonaws.com"
  source_arn     = each.value.arn
  source_account = local.account_id
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name}-dead-letters"
  alarm_description   = "Findings that could not be remediated after retries are waiting in ${aws_sqs_queue.dlq.name}."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  alarm_description   = "${var.name} failed to remediate at least one finding; the reason is in the finding note and the log."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.remediator.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}
