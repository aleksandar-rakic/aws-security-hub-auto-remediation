from __future__ import annotations

from typing import Any

import boto3
import pytest

from conftest import ACCOUNT, REGION, event
from remediator.quarantine import QUARANTINE_GROUP


def _instance(tags: dict[str, str] | None = None) -> tuple[str, str]:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24")["Subnet"]["SubnetId"]
    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    spec: dict[str, Any] = {}
    if tags:
        spec["TagSpecifications"] = [
            {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        ]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet,
        SecurityGroupIds=[web],
        **spec,
    )["Instances"][0]["InstanceId"]
    return instance, web


def guardduty_finding(instance_id: str, severity: str = "HIGH") -> dict[str, Any]:
    return {
        "Id": f"arn:aws:guardduty:{REGION}:{ACCOUNT}:detector/d1/finding/f1",
        "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/guardduty",
        "ProductName": "GuardDuty",
        "AwsAccountId": ACCOUNT,
        "Region": REGION,
        "Types": ["TTPs/Command and Control/Backdoor:EC2-C&CActivity.B"],
        "Severity": {"Label": severity},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "Resources": [
            {
                "Type": "AwsEc2Instance",
                "Id": f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance_id}",
            }
        ],
    }


def _describe(instance_id: str) -> dict[str, Any]:
    ec2 = boto3.client("ec2", region_name=REGION)
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def test_quarantine_is_off_by_default(run, securityhub):
    instance, web = _instance()

    result = run(event(guardduty_finding(instance)))

    assert result["results"][0]["status"] == "skipped"
    assert [g["GroupId"] for g in _describe(instance)["SecurityGroups"]] == [web]
    assert "turned off" in securityhub.last()[1]


def test_instance_is_isolated_and_snapshotted(run, securityhub):
    instance, web = _instance()

    run(event(guardduty_finding(instance, "CRITICAL")), quarantine_enabled=True)

    ec2 = boto3.client("ec2", region_name=REGION)
    described = _describe(instance)
    (group,) = described["SecurityGroups"]
    assert group["GroupName"] == QUARANTINE_GROUP
    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [group["GroupId"]]}]
    )["SecurityGroupRules"]
    assert rules == []

    tags = {t["Key"]: t["Value"] for t in described["Tags"]}
    assert tags["quarantine"] == "true"
    assert tags["quarantine-previous-groups"] == web

    snapshots = ec2.describe_snapshots(
        Filters=[{"Name": "tag:quarantine-instance", "Values": [instance]}]
    )["Snapshots"]
    assert len(snapshots) == 1
    assert securityhub.last()[0] == "RESOLVED"


def test_second_finding_reuses_the_group_and_changes_nothing(run, securityhub):
    instance, _ = _instance()
    run(event(guardduty_finding(instance)), quarantine_enabled=True)

    result = run(event(guardduty_finding(instance)), quarantine_enabled=True)

    assert result["results"][0]["status"] == "compliant"
    ec2 = boto3.client("ec2", region_name=REGION)
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [QUARANTINE_GROUP]}]
    )["SecurityGroups"]
    assert len(groups) == 1


def test_exempt_instance_is_left_alone(run, securityhub):
    instance, web = _instance(tags={"auto-remediation": "skip"})

    run(event(guardduty_finding(instance)), quarantine_enabled=True)

    assert [g["GroupId"] for g in _describe(instance)["SecurityGroups"]] == [web]
    assert securityhub.last()[0] == "NOTIFIED"


@pytest.mark.parametrize("severity", ["LOW", "MEDIUM"])
def test_lower_severities_are_ignored(run, securityhub, severity):
    instance, _ = _instance()

    result = run(event(guardduty_finding(instance, severity)), quarantine_enabled=True)

    assert result["results"][0]["status"] == "ignored"
    assert securityhub.updates == []
