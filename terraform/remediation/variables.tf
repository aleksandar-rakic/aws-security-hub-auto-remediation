variable "region" {
  description = "Region of the Security Hub administrator (or aggregation region). Findings arrive here."
  type        = string
}

variable "name" {
  description = "Name for the Lambda function and the resources around it."
  type        = string
  default     = "security-hub-remediation"
}

variable "controls" {
  description = "Security Hub control IDs to remediate automatically. null (the default) means every supported control; start with a short list and widen it as you gain confidence."
  type        = list(string)
  default     = null

  validation {
    condition     = var.controls == null || alltrue([for c in coalesce(var.controls, []) : contains(local.supported_controls, c)])
    error_message = "Supported controls: ${join(", ", local.supported_controls)}."
  }
}

variable "dry_run" {
  description = "Report what would change on each finding without changing anything. Turn off once the notes look right."
  type        = bool
  default     = true
}

variable "quarantine_enabled" {
  description = "Isolate EC2 instances named in HIGH or CRITICAL GuardDuty findings. Disruptive, so off by default."
  type        = bool
  default     = false
}

variable "member_role_name" {
  description = "Role the Lambda assumes in member accounts (see ../member-role). Empty: only the Lambda's own account is remediated."
  type        = string
  default     = ""
}

variable "exemption_tag" {
  description = "Resources carrying this tag are never changed; their findings get a note instead."
  type = object({
    key   = string
    value = string
  })
  default = {
    key   = "auto-remediation"
    value = "skip"
  }
}

variable "reserved_concurrency" {
  description = "Upper bound on concurrent remediations. null leaves the function on unreserved concurrency."
  type        = number
  default     = null
}

variable "log_retention_days" {
  description = "Retention of the Lambda's log group, which is the audit trail of every change."
  type        = number
  default     = 365
}

variable "alarm_actions" {
  description = "SNS topic ARNs notified when remediation fails or events reach the dead-letter queue."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    project = "security-hub-auto-remediation"
  }
}
