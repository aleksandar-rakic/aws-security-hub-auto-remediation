from __future__ import annotations

import boto3

from conftest import ACCOUNT, REGION, control_finding, event


def _default_group() -> tuple[str, str, str]:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.2.0.0/16")["Vpc"]["VpcId"]
    group = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return vpc, group, f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{group}"


def _rules(group: str) -> list[dict]:
    ec2 = boto3.client("ec2", region_name=REGION)
    return ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group]}])[
        "SecurityGroupRules"
    ]


def test_unused_default_group_is_emptied(run, securityhub):
    _, group, arn = _default_group()
    assert _rules(group), "a new default group allows traffic"

    run(event(control_finding("EC2.2", "AwsEc2SecurityGroup", arn)))

    assert _rules(group) == []
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "from unused default group" in note


def test_default_group_in_use_is_left_alone(run, securityhub):
    vpc, group, arn = _default_group()
    ec2 = boto3.client("ec2", region_name=REGION)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.2.1.0/24")["Subnet"]["SubnetId"]
    eni = ec2.create_network_interface(SubnetId=subnet, Groups=[group])["NetworkInterface"]
    before = _rules(group)

    result = run(event(control_finding("EC2.2", "AwsEc2SecurityGroup", arn)))

    assert result["results"][0]["status"] == "skipped"
    assert _rules(group) == before
    status, note = securityhub.last()
    assert status == "NOTIFIED"
    assert eni["NetworkInterfaceId"] in note


def test_non_default_group_is_refused(run, securityhub):
    vpc, _, _ = _default_group()
    ec2 = boto3.client("ec2", region_name=REGION)
    other = ec2.create_security_group(GroupName="app", Description="app", VpcId=vpc)["GroupId"]
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{other}"

    run(event(control_finding("EC2.2", "AwsEc2SecurityGroup", arn)))

    assert _rules(other), "a non-default group must keep its rules"
    assert "not a VPC default security group" in securityhub.last()[1]


def test_already_empty_default_group_is_compliant(run, securityhub):
    _, _, arn = _default_group()
    run(event(control_finding("EC2.2", "AwsEc2SecurityGroup", arn)))

    result = run(event(control_finding("EC2.2", "AwsEc2SecurityGroup", arn)))

    assert result["results"][0]["status"] == "compliant"
