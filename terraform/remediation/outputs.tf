output "function_name" {
  description = "Name of the remediation Lambda."
  value       = aws_lambda_function.remediator.function_name
}

output "role_arn" {
  description = "Execution role ARN; pass it to ../member-role as remediator_role_arn."
  value       = aws_iam_role.remediator.arn
}

output "dead_letter_queue_url" {
  description = "Events that failed after retries wait here."
  value       = aws_sqs_queue.dlq.url
}

output "event_rules" {
  description = "EventBridge rules that invoke the Lambda."
  value       = { for key, rule in local.rules : key => rule.name }
}

output "dry_run" {
  description = "Whether the Lambda only reports (true) or changes resources (false)."
  value       = var.dry_run
}
