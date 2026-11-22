output "policy_ids" {
  description = "Service control policy IDs by name."
  value       = { for name, policy in aws_organizations_policy.this : name => policy.id }
}

output "policy_sizes" {
  description = "Characters used by each policy; the SCP limit is 5,120."
  value       = { for name, policy in aws_organizations_policy.this : name => length(policy.content) }
}
