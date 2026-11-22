"""Isolate an EC2 instance named in a high or critical GuardDuty finding.

The instance is moved into a security group with no rules and its EBS volumes
are snapshotted for forensics. It is not stopped or terminated, so memory and
running processes stay available to whoever investigates.

Security groups track connections: a session that was already open when the
group changed can stay open until it goes idle. Network ACLs or stopping the
instance are the follow-up if that matters for the incident.
"""

from __future__ import annotations

from typing import Any

from .actions import Context, Outcome, Skipped
from .findings import Finding

QUARANTINE_GROUP = "quarantine-no-traffic"
SEVERITIES = ("HIGH", "CRITICAL")


def applies_to(finding: Finding) -> bool:
    return (
        finding.product_name == "GuardDuty"
        and finding.resource_type == "AwsEc2Instance"
        and finding.severity in SEVERITIES
    )


def _quarantine_group(ec2: Any, vpc_id: str, dry_run: bool) -> str:
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [QUARANTINE_GROUP]},
        ]
    )["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]
    if dry_run:
        return f"(new {QUARANTINE_GROUP} group)"
    group_id = ec2.create_security_group(
        GroupName=QUARANTINE_GROUP,
        Description="No inbound or outbound traffic; used to isolate instances",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "purpose", "Value": "quarantine"}]}
        ],
    )["GroupId"]
    # New groups allow all outbound traffic; remove that rule.
    ec2.revoke_security_group_egress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    return group_id


def quarantine_instance(ctx: Context, finding: Finding) -> Outcome:
    if not ctx.quarantine_enabled:
        raise Skipped("instance quarantine is turned off (QUARANTINE_ENABLED)")
    instance_id = finding.resource_name
    ec2 = ctx.client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instance = reservations[0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    ctx.check_exemption(tags, f"instance {instance_id}")

    group_id = _quarantine_group(ec2, instance["VpcId"], ctx.dry_run)
    previous = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
    if previous == [group_id]:
        return Outcome(False, f"{instance_id} is already in {group_id}")

    volumes = [m["Ebs"]["VolumeId"] for m in instance.get("BlockDeviceMappings", []) if "Ebs" in m]
    if not ctx.dry_run:
        for volume in volumes:
            ec2.create_snapshot(
                VolumeId=volume,
                Description=f"Forensic copy of {volume} from {instance_id}"[:255],
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "quarantine-instance", "Value": instance_id},
                            {"Key": "finding", "Value": finding.id[:256]},
                        ],
                    }
                ],
            )
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[group_id])
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "quarantine", "Value": "true"},
                {"Key": "quarantine-previous-groups", "Value": " ".join(previous)[:256]},
            ],
        )
    return Outcome(
        True,
        f"isolated {instance_id} in {group_id} (was {', '.join(previous) or 'none'}) "
        f"and snapshotted {len(volumes)} volume(s)",
    )
