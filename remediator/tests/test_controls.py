from __future__ import annotations

import boto3
import pytest

from conftest import ACCOUNT, REGION, control_finding, event
from remediator.actions import FULL_BLOCK
from remediator.handler import RemediationError

# S3.8 / S3.1


def _bucket(name: str, tags: dict[str, str] | None = None) -> str:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    if tags:
        tag_set = [{"Key": k, "Value": v} for k, v in tags.items()]
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": tag_set})
    return f"arn:aws:s3:::{name}"


def _bucket_block(name: str) -> dict[str, bool]:
    s3 = boto3.client("s3", region_name=REGION)
    return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]


def test_bucket_public_access_is_blocked(run, securityhub):
    arn = _bucket("reports")
    result = run(event(control_finding("S3.8", "AwsS3Bucket", arn)))

    assert result["results"][0]["status"] == "remediated"
    assert _bucket_block("reports") == FULL_BLOCK
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "bucket reports" in note


def test_bucket_already_blocked_is_resolved_without_change(run, securityhub):
    arn = _bucket("locked")
    boto3.client("s3", region_name=REGION).put_public_access_block(
        Bucket="locked", PublicAccessBlockConfiguration=FULL_BLOCK
    )
    result = run(event(control_finding("S3.8", "AwsS3Bucket", arn)))

    assert result["results"][0]["status"] == "compliant"
    assert securityhub.last()[0] == "RESOLVED"


def test_exempt_bucket_is_left_alone(run, securityhub):
    arn = _bucket("public-website", tags={"auto-remediation": "skip"})
    result = run(event(control_finding("S3.8", "AwsS3Bucket", arn)))

    assert result["results"][0]["status"] == "skipped"
    status, note = securityhub.last()
    assert status == "NOTIFIED"
    assert "auto-remediation=skip" in note
    with pytest.raises(Exception, match="NoSuchPublicAccessBlockConfiguration"):
        _bucket_block("public-website")


def test_dry_run_reports_but_does_not_change(run, securityhub):
    arn = _bucket("draft")
    result = run(event(control_finding("S3.8", "AwsS3Bucket", arn)), dry_run=True)

    assert result["results"][0]["status"] == "dry_run"
    status, note = securityhub.last()
    assert status == "NOTIFIED"
    assert note.startswith("Dry run, nothing changed. Would have: turned on")
    with pytest.raises(Exception, match="NoSuchPublicAccessBlockConfiguration"):
        _bucket_block("draft")


def test_account_public_access_block(run, securityhub):
    run(event(control_finding("S3.1", "AwsAccount", f"AWS::::Account:{ACCOUNT}")))

    s3control = boto3.client("s3control", region_name=REGION)
    config = s3control.get_public_access_block(AccountId=ACCOUNT)
    assert config["PublicAccessBlockConfiguration"] == FULL_BLOCK
    assert securityhub.last()[0] == "RESOLVED"


def test_missing_bucket_fails_the_invocation_and_notes_the_finding(run, securityhub):
    finding = control_finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::gone")
    with pytest.raises(RemediationError, match="1 of 1"):
        run(event(finding))

    status, note = securityhub.last()
    assert status == "NOTIFIED"
    assert note.startswith("Automatic remediation failed: NoSuchBucket")


# EC2.7


def test_ebs_default_encryption(run, securityhub):
    ec2 = boto3.client("ec2", region_name=REGION)
    assert not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]

    run(event(control_finding("EC2.7", "AwsAccount", f"AWS::::Account:{ACCOUNT}")))

    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert securityhub.last()[0] == "RESOLVED"


# EC2.13 / EC2.14 / EC2.53 / EC2.54


def _group(rules: list[dict], tags: dict[str, str] | None = None) -> str:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    group = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=rules)
    if tags:
        ec2.create_tags(Resources=[group], Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
    return group


def _ingress(group: str) -> list[tuple]:
    ec2 = boto3.client("ec2", region_name=REGION)
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group]}])
    return sorted(
        (r["IpProtocol"], r.get("FromPort"), r.get("CidrIpv4") or r.get("CidrIpv6"))
        for r in rules["SecurityGroupRules"]
        if not r["IsEgress"]
    )


def _tcp(port: int, cidr: str = "0.0.0.0/0") -> dict:
    ranges = (
        {"Ipv6Ranges": [{"CidrIpv6": cidr}]} if ":" in cidr else {"IpRanges": [{"CidrIp": cidr}]}
    )
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, **ranges}


@pytest.mark.parametrize("control", ["EC2.13", "EC2.14", "EC2.53", "EC2.54"])
def test_world_open_admin_ports_are_revoked_and_nothing_else(run, securityhub, control):
    group = _group([_tcp(22), _tcp(3389, "::/0"), _tcp(443), _tcp(22, "10.0.0.0/8")])
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"

    run(event(control_finding(control, "AwsEc2SecurityGroup", arn)))

    assert _ingress(group) == [("tcp", 22, "10.0.0.0/8"), ("tcp", 443, "0.0.0.0/0")]
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "revoked 2 ingress rule(s)" in note


def test_all_traffic_and_port_ranges_count_as_open(run):
    group = _group(
        [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {
                "IpProtocol": "tcp",
                "FromPort": 20,
                "ToPort": 30,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ]
    )
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"

    run(event(control_finding("EC2.13", "AwsEc2SecurityGroup", arn)))

    assert _ingress(group) == []


def test_exempt_security_group_is_left_alone(run, securityhub):
    group = _group([_tcp(22)], tags={"auto-remediation": "skip"})
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"

    run(event(control_finding("EC2.13", "AwsEc2SecurityGroup", arn)))

    assert _ingress(group) == [("tcp", 22, "0.0.0.0/0")]
    assert securityhub.last()[0] == "NOTIFIED"


# KMS.4


def test_kms_key_rotation(run, securityhub):
    kms = boto3.client("kms", region_name=REGION)
    key = kms.create_key()["KeyMetadata"]["Arn"]

    run(event(control_finding("KMS.4", "AwsKmsKey", key)))

    assert kms.get_key_rotation_status(KeyId=key)["KeyRotationEnabled"]
    assert securityhub.last()[0] == "RESOLVED"


def test_exempt_kms_key_is_left_alone(run, securityhub):
    kms = boto3.client("kms", region_name=REGION)
    key = kms.create_key(Tags=[{"TagKey": "auto-remediation", "TagValue": "SKIP"}])
    arn = key["KeyMetadata"]["Arn"]

    run(event(control_finding("KMS.4", "AwsKmsKey", arn)))

    assert not kms.get_key_rotation_status(KeyId=arn)["KeyRotationEnabled"]
    assert securityhub.last()[0] == "NOTIFIED"


# EC2.19


def test_high_risk_ports_are_revoked_and_web_ports_kept(run, securityhub):
    group = _group([_tcp(3306), _tcp(9200, "::/0"), _tcp(443), _tcp(80), _tcp(5432, "10.0.0.0/8")])
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"

    run(event(control_finding("EC2.19", "AwsEc2SecurityGroup", arn)))

    assert _ingress(group) == [
        ("tcp", 80, "0.0.0.0/0"),
        ("tcp", 443, "0.0.0.0/0"),
        ("tcp", 5432, "10.0.0.0/8"),
    ]
    assert "revoked 2 ingress rule(s)" in securityhub.last()[1]


def test_admin_port_controls_do_not_touch_other_high_risk_ports(run):
    group = _group([_tcp(22), _tcp(3306)])
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"

    run(event(control_finding("EC2.13", "AwsEc2SecurityGroup", arn)))

    assert _ingress(group) == [("tcp", 3306, "0.0.0.0/0")]
