# Controls the remediator has an action for. Must match CONTROL_ACTIONS in
# remediator/src/remediator/actions.py; a pytest compares the two.
locals {
  supported_controls = [
    "EC2.1",
    "EC2.2",
    "EC2.7",
    "EC2.13",
    "EC2.14",
    "EC2.53",
    "EC2.54",
    "KMS.4",
    "S3.1",
    "S3.5",
    "S3.8",
  ]

  controls = coalesce(var.controls, local.supported_controls)
}
