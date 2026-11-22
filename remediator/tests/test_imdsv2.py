from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3

from conftest import ACCOUNT, REGION, control_finding, event


def _instance(tags: dict[str, str] | None = None, tokens: str = "optional") -> tuple[str, str]:
    ec2 = boto3.client("ec2", region_name=REGION)
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    spec = {}
    if tags:
        spec["TagSpecifications"] = [
            {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        ]
    instance = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        MetadataOptions={"HttpTokens": tokens, "HttpEndpoint": "enabled"},
        **spec,
    )["Instances"][0]["InstanceId"]
    return instance, f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance}"


def _tokens(instance: str) -> str:
    ec2 = boto3.client("ec2", region_name=REGION)
    described = ec2.describe_instances(InstanceIds=[instance])["Reservations"][0]["Instances"][0]
    return described["MetadataOptions"]["HttpTokens"]


def _imdsv1_calls(instance: str, count: int) -> None:
    boto3.client("cloudwatch", region_name=REGION).put_metric_data(
        Namespace="AWS/EC2",
        MetricData=[
            {
                "MetricName": "MetadataNoToken",
                "Dimensions": [{"Name": "InstanceId", "Value": instance}],
                "Timestamp": datetime.now(UTC) - timedelta(hours=3),  # metrics land with a delay
                "Value": count,
            }
        ],
    )


def test_imdsv2_is_required_when_v1_is_unused(run, securityhub):
    instance, arn = _instance()

    run(event(control_finding("EC2.8", "AwsEc2Instance", arn)))

    assert _tokens(instance) == "required"
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "no IMDSv1 requests in the last 14 days" in note


def test_instance_still_using_imdsv1_is_left_alone(run, securityhub):
    instance, arn = _instance()
    _imdsv1_calls(instance, 42)

    result = run(event(control_finding("EC2.8", "AwsEc2Instance", arn)))

    assert result["results"][0]["status"] == "skipped"
    assert _tokens(instance) == "optional"
    assert "made 42 IMDSv1 request(s)" in securityhub.last()[1]


def test_exempt_instance_is_left_alone(run, securityhub):
    instance, arn = _instance(tags={"auto-remediation": "skip"})

    run(event(control_finding("EC2.8", "AwsEc2Instance", arn)))

    assert _tokens(instance) == "optional"
    assert securityhub.last()[0] == "NOTIFIED"


def test_instance_already_on_imdsv2_is_compliant(run, securityhub):
    _, arn = _instance(tokens="required")

    result = run(event(control_finding("EC2.8", "AwsEc2Instance", arn)))

    assert result["results"][0]["status"] == "compliant"
