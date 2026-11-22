variable "region" {
  description = "Region for the Organizations API endpoint."
  type        = string
  default     = "us-east-1"
}

variable "target_ids" {
  description = "OU IDs (ou-...) or account IDs the policies are attached to. Test on a sandbox OU first."
  type        = list(string)

  validation {
    condition     = alltrue([for id in var.target_ids : can(regex("^(ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}|[0-9]{12})$", id))])
    error_message = "Each target must be an OU ID (ou-xxxx-xxxxxxxx) or a 12-digit account ID. Do not attach SCPs to the root until tested."
  }
}

variable "exempt_principal_arns" {
  description = "ARN patterns (ArnLike) of break-glass and deployment roles that the deny statements do not apply to."
  type        = list(string)
  default     = []
}

variable "protected_role_names" {
  description = "Role name patterns that only exempt principals may change: the remediation and member roles."
  type        = list(string)
  default     = ["security-hub-remediation*"]
}

variable "allowed_regions" {
  description = "Regions where regional services may be used. Empty: no region restriction is created."
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
