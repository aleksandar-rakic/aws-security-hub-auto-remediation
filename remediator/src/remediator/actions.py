"""Remediation actions for Security Hub controls.

Every action is idempotent: it reads the current state first, changes it only
when it is non-compliant, and reports whether it changed anything. Under dry
run it reads and reports but never writes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from .findings import Finding

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
ADMIN_PORTS = (22, 3389)
ANYWHERE = ("0.0.0.0/0", "::/0")


class Skipped(Exception):
    """The finding is left for a person: the resource is exempt or out of reach."""


@dataclass(frozen=True)
class Outcome:
    changed: bool
    summary: str


@dataclass
class Context:
    session: Any  # boto3.Session in the finding's account and region
    dry_run: bool
    exemption_key: str
    exemption_value: str
    quarantine_enabled: bool = False
    _clients: dict[str, Any] = field(default_factory=dict, repr=False)

    def client(self, service: str) -> Any:
        if service not in self._clients:
            self._clients[service] = self.session.client(service)
        return self._clients[service]

    def exempt(self, tags: dict[str, str]) -> bool:
        return tags.get(self.exemption_key, "").lower() == self.exemption_value.lower()

    def check_exemption(self, tags: dict[str, str], what: str) -> None:
        if self.exempt(tags):
            raise Skipped(f"{what} is tagged {self.exemption_key}={self.exemption_value}")


Action = Callable[[Context, Finding], Outcome]


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _tags(pairs: list[dict[str, str]], key: str = "Key", value: str = "Value") -> dict[str, str]:
    return {p[key]: p[value] for p in pairs}


def ec2_tags(ec2: Any, resource_id: str) -> dict[str, str]:
    resp = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])
    return _tags(resp["Tags"])


def _bucket_tags(s3: Any, bucket: str) -> dict[str, str]:
    try:
        return _tags(s3.get_bucket_tagging(Bucket=bucket)["TagSet"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchTagSet":
            raise
        return {}


# S3.8 - S3 general purpose buckets should block public access


def block_bucket_public_access(ctx: Context, finding: Finding) -> Outcome:
    bucket = finding.resource_name
    s3 = ctx.client("s3")
    ctx.check_exemption(_bucket_tags(s3, bucket), f"bucket {bucket}")

    try:
        current = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        current = {}
    if current == FULL_BLOCK:
        return Outcome(False, f"bucket {bucket} already blocks all public access")
    if not ctx.dry_run:
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=FULL_BLOCK)
    return Outcome(True, f"turned on all four public access block settings on bucket {bucket}")


# S3.1 - S3 general purpose buckets should have block public access settings enabled
# (the account-level setting)


def block_account_public_access(ctx: Context, finding: Finding) -> Outcome:
    s3control = ctx.client("s3control")
    account = finding.account_id
    try:
        current = s3control.get_public_access_block(AccountId=account)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as exc:
        if _error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        current = {}
    if current == FULL_BLOCK:
        return Outcome(False, f"account {account} already blocks all S3 public access")
    if not ctx.dry_run:
        s3control.put_public_access_block(
            AccountId=account, PublicAccessBlockConfiguration=FULL_BLOCK
        )
    return Outcome(True, f"turned on account-level S3 public access block in {account}")


# EC2.7 - EBS default encryption should be enabled


def enable_ebs_default_encryption(ctx: Context, finding: Finding) -> Outcome:
    ec2 = ctx.client("ec2")
    if ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        return Outcome(False, f"EBS default encryption is already on in {finding.region}")
    if not ctx.dry_run:
        ec2.enable_ebs_encryption_by_default()
    return Outcome(True, f"turned on EBS default encryption in {finding.region}")


# EC2.13 / EC2.14 / EC2.53 / EC2.54 - security groups should not allow ingress
# from 0.0.0.0/0 or ::/0 to the remote administration ports


def _opens_admin_port(rule: dict[str, Any]) -> bool:
    if rule.get("IsEgress"):
        return False
    if rule.get("CidrIpv4") not in ANYWHERE and rule.get("CidrIpv6") not in ANYWHERE:
        return False
    protocol = str(rule.get("IpProtocol"))
    if protocol == "-1":
        return True
    if protocol not in ("tcp", "udp", "6", "17"):
        return False
    low, high = rule.get("FromPort", -1), rule.get("ToPort", -1)
    return any(low <= port <= high for port in ADMIN_PORTS)


def close_admin_ports(ctx: Context, finding: Finding) -> Outcome:
    group_id = finding.resource_name
    ec2 = ctx.client("ec2")
    ctx.check_exemption(ec2_tags(ec2, group_id), f"security group {group_id}")

    paginator = ec2.get_paginator("describe_security_group_rules")
    pages = paginator.paginate(Filters=[{"Name": "group-id", "Values": [group_id]}])
    offending = [r for page in pages for r in page["SecurityGroupRules"] if _opens_admin_port(r)]
    if not offending:
        return Outcome(False, f"{group_id} has no ingress from anywhere to ports 22 or 3389")

    described = ", ".join(
        f"{r['SecurityGroupRuleId']} ({r['IpProtocol']} {r.get('FromPort')}-{r.get('ToPort')} "
        f"from {r.get('CidrIpv4') or r.get('CidrIpv6')})"
        for r in offending
    )
    if not ctx.dry_run:
        ec2.revoke_security_group_ingress(
            GroupId=group_id, SecurityGroupRuleIds=[r["SecurityGroupRuleId"] for r in offending]
        )
    return Outcome(True, f"revoked {len(offending)} ingress rule(s) on {group_id}: {described}")


# KMS.4 - AWS KMS key rotation should be enabled


def enable_kms_key_rotation(ctx: Context, finding: Finding) -> Outcome:
    key = finding.resource_id
    kms = ctx.client("kms")
    tags = _tags(kms.list_resource_tags(KeyId=key).get("Tags", []), "TagKey", "TagValue")
    ctx.check_exemption(tags, f"key {finding.resource_name}")
    if kms.get_key_rotation_status(KeyId=key)["KeyRotationEnabled"]:
        return Outcome(False, f"rotation is already on for key {finding.resource_name}")
    if not ctx.dry_run:
        kms.enable_key_rotation(KeyId=key)
    return Outcome(True, f"turned on automatic rotation for key {finding.resource_name}")


# S3.5 - S3 general purpose buckets should require requests to use SSL

TLS_STATEMENT_SID = "DenyInsecureTransport"


def _denies_insecure_transport(statement: dict[str, Any]) -> bool:
    if statement.get("Effect") != "Deny":
        return False
    conditions = statement.get("Condition") or {}
    for operator, values in conditions.items():
        if operator.lower() != "bool":
            continue
        for key, value in values.items():
            flag = value[0] if isinstance(value, list) and len(value) == 1 else value
            if key.lower() == "aws:securetransport" and str(flag).lower() == "false":
                return True
    return False


def require_tls(ctx: Context, finding: Finding) -> Outcome:
    bucket = finding.resource_name
    s3 = ctx.client("s3")
    ctx.check_exemption(_bucket_tags(s3, bucket), f"bucket {bucket}")

    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchBucketPolicy":
            raise
        policy = {"Version": "2012-10-17", "Statement": []}
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if any(_denies_insecure_transport(s) for s in statements):
        return Outcome(False, f"bucket {bucket} already denies requests without TLS")

    arn = f"arn:{finding.partition}:s3:::{bucket}"
    deny = {
        "Sid": TLS_STATEMENT_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [arn, f"{arn}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    if not ctx.dry_run:
        policy["Statement"] = [*statements, deny]
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    kept = f", keeping its {len(statements)} existing statement(s)" if statements else ""
    return Outcome(
        True, f"added a deny-without-TLS statement to the policy of bucket {bucket}{kept}"
    )


# EC2.2 - VPC default security groups should not allow inbound or outbound traffic


def empty_default_security_group(ctx: Context, finding: Finding) -> Outcome:
    group_id = finding.resource_name
    ec2 = ctx.client("ec2")
    (group,) = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    if group["GroupName"] != "default":
        raise Skipped(f"{group_id} is not a VPC default security group")
    ctx.check_exemption(_tags(group.get("Tags", [])), f"security group {group_id}")

    # Emptying a default group that is still attached would cut those resources
    # off. Leave it to a person to move them to dedicated groups first.
    in_use = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [group_id]}])[
        "NetworkInterfaces"
    ]
    if in_use:
        listed = ", ".join(ni["NetworkInterfaceId"] for ni in in_use[:5])
        more = f" and {len(in_use) - 5} more" if len(in_use) > 5 else ""
        raise Skipped(
            f"default group {group_id} is still used by {len(in_use)} network interface(s) "
            f"({listed}{more}); move them to dedicated groups first"
        )

    paginator = ec2.get_paginator("describe_security_group_rules")
    pages = paginator.paginate(Filters=[{"Name": "group-id", "Values": [group_id]}])
    rules = [r for page in pages for r in page["SecurityGroupRules"]]
    ingress = [r["SecurityGroupRuleId"] for r in rules if not r["IsEgress"]]
    egress = [r["SecurityGroupRuleId"] for r in rules if r["IsEgress"]]
    if not rules:
        return Outcome(False, f"default group {group_id} already has no rules")
    if not ctx.dry_run:
        if ingress:
            ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=ingress)
        if egress:
            ec2.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=egress)
    return Outcome(
        True,
        f"removed {len(ingress)} inbound and {len(egress)} outbound rule(s) "
        f"from unused default group {group_id}",
    )


# EC2.1 - EBS snapshots should not be publicly restorable
# (evaluated per account and region, so the finding names the account)


def _is_public(ec2: Any, snapshot_id: str) -> bool:
    permissions = ec2.describe_snapshot_attribute(
        SnapshotId=snapshot_id, Attribute="createVolumePermission"
    )["CreateVolumePermissions"]
    return any(p.get("Group") == "all" for p in permissions)


def make_snapshots_private(ctx: Context, finding: Finding) -> Outcome:
    ec2 = ctx.client("ec2")
    paginator = ec2.get_paginator("describe_snapshots")
    pages = paginator.paginate(OwnerIds=["self"], RestorableByUserIds=["all"])
    candidates = [s for page in pages for s in page["Snapshots"]]
    public = [s for s in candidates if _is_public(ec2, s["SnapshotId"])]

    exempt = [s["SnapshotId"] for s in public if ctx.exempt(_tags(s.get("Tags", [])))]
    to_fix = [s["SnapshotId"] for s in public if s["SnapshotId"] not in exempt]
    if not to_fix:
        if exempt:
            raise Skipped(
                f"only exempt snapshots are public in {finding.region}: {', '.join(exempt)}"
            )
        return Outcome(False, f"no publicly restorable snapshots in {finding.region}")

    if not ctx.dry_run:
        for snapshot_id in to_fix:
            ec2.modify_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute="createVolumePermission",
                OperationType="remove",
                GroupNames=["all"],
            )
    kept = f"; left exempt {', '.join(exempt)} public" if exempt else ""
    return Outcome(
        True,
        f"made {len(to_fix)} snapshot(s) private in {finding.region}: {', '.join(to_fix)}{kept}",
    )


# EC2.8 - EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)

IMDSV1_LOOKBACK = timedelta(days=14)


def _imdsv1_calls(cloudwatch: Any, instance_id: str) -> int:
    """IMDSv1 requests the instance made recently (CloudWatch MetadataNoToken)."""
    end = datetime.now(UTC)
    datapoints = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="MetadataNoToken",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=end - IMDSV1_LOOKBACK,
        EndTime=end,
        Period=86400,
        Statistics=["Sum"],
    )["Datapoints"]
    return int(sum(d["Sum"] for d in datapoints))


def require_imdsv2(ctx: Context, finding: Finding) -> Outcome:
    instance_id = finding.resource_name
    ec2 = ctx.client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    instance = reservations[0]["Instances"][0]
    ctx.check_exemption(_tags(instance.get("Tags", [])), f"instance {instance_id}")

    options = instance.get("MetadataOptions", {})
    if options.get("HttpTokens") == "required" or options.get("HttpEndpoint") == "disabled":
        return Outcome(False, f"{instance_id} already requires IMDSv2")

    # Turning IMDSv1 off under software that still uses it breaks that software
    # (credentials, region lookup). Only switch instances that have not used it.
    calls = _imdsv1_calls(ctx.client("cloudwatch"), instance_id)
    if calls:
        days = IMDSV1_LOOKBACK.days
        raise Skipped(
            f"{instance_id} made {calls} IMDSv1 request(s) in the last {days} days; "
            "update its SDKs or agents first (CloudWatch metric MetadataNoToken)"
        )

    if not ctx.dry_run:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled"
        )
    return Outcome(
        True,
        f"set HttpTokens=required on {instance_id} "
        f"(no IMDSv1 requests in the last {IMDSV1_LOOKBACK.days} days)",
    )


CONTROL_ACTIONS: dict[str, Action] = {
    "S3.1": block_account_public_access,
    "S3.8": block_bucket_public_access,
    "EC2.7": enable_ebs_default_encryption,
    "EC2.13": close_admin_ports,
    "EC2.14": close_admin_ports,
    "EC2.53": close_admin_ports,
    "EC2.54": close_admin_ports,
    "KMS.4": enable_kms_key_rotation,
    "S3.5": require_tls,
    "EC2.2": empty_default_security_group,
    "EC2.1": make_snapshots_private,
    "EC2.8": require_imdsv2,
}


def select_action(finding: Finding) -> Action | None:
    if finding.control_id in CONTROL_ACTIONS:
        return CONTROL_ACTIONS[finding.control_id]
    return None
