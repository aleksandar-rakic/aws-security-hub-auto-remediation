# Controls the remediator has an action for. Must match CONTROL_ACTIONS in
# remediator/src/remediator/actions.py; a pytest compares the two.
locals {
  supported_controls = [
    "EC2.1",
    "EC2.2",
    "EC2.7",
    "EC2.8",
    "EC2.13",
    "EC2.14",
    "EC2.19",
    "EC2.53",
    "EC2.54",
    "ECR.1",
    "KMS.4",
    "S3.1",
    "S3.5",
    "S3.8",
    "SQS.1",
  ]

  # Supported but not remediated unless listed in var.controls: closing these
  # can take down a service that is meant to be public (8080, 3000, 5000, ...).
  opt_in_controls = ["EC2.19"]

  controls = coalesce(var.controls, [for c in local.supported_controls : c if !contains(local.opt_in_controls, c)])
}
