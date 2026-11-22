data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "remediator" {
  name               = var.name
  description        = "Execution role of the ${var.name} Lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.remediator.arn}:*"]
  }

  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }

  statement {
    sid       = "DeadLetters"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  statement {
    sid       = "RecordOutcomeOnFindings"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["arn:${local.partition}:securityhub:${var.region}:${local.account_id}:hub/default"]
  }

  dynamic "statement" {
    for_each = var.member_role_name == "" ? [] : [var.member_role_name]

    content {
      sid       = "AssumeMemberRole"
      actions   = ["sts:AssumeRole"]
      resources = ["arn:${local.partition}:iam::*:role/${statement.value}"]
    }
  }
}

resource "aws_iam_role_policy" "remediator" {
  name   = "runtime"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.runtime.json
}

# The same permissions the member-role grants in other accounts, so the
# administrator account itself is remediated too.
resource "aws_iam_role_policy" "remediation" {
  name   = "remediation"
  role   = aws_iam_role.remediator.id
  policy = file("${path.module}/../policies/remediation-permissions.json")
}
