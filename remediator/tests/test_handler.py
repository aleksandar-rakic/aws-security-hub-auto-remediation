from __future__ import annotations

import boto3

from conftest import REGION, control_finding, event
from remediator.findings import Finding
from remediator.handler import NOTE_LIMIT, Sessions, Settings, _update_finding


def test_unknown_controls_are_ignored_without_touching_the_finding(run, securityhub):
    result = run(event(control_finding("IAM.6", "AwsAccount", "AWS::::Account:123456789012")))

    assert result == {
        "results": [{"finding": result["results"][0]["finding"], "status": "ignored"}]
    }
    assert securityhub.updates == []


def test_legacy_control_id_from_product_fields():
    raw = control_finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::logs", legacy=True)
    finding = Finding.from_asff(raw)

    assert finding.control_id == "S3.8"
    assert finding.resource_name == "logs"
    assert finding.partition == "aws"


def test_every_finding_in_the_event_is_processed(run, securityhub):
    s3 = boto3.client("s3", region_name=REGION)
    for name in ("one", "two"):
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})

    result = run(
        event(
            control_finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::one"),
            control_finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::two"),
        )
    )

    assert [r["status"] for r in result["results"]] == ["remediated", "remediated"]
    assert len(securityhub.updates) == 2


def test_member_account_without_role_is_skipped(run, securityhub):
    finding = control_finding(
        "EC2.7", "AwsAccount", "AWS::::Account:111122223333", account="111122223333"
    )

    result = run(event(finding))

    assert result["results"][0]["status"] == "skipped"
    status, note = securityhub.last()
    assert status == "NOTIFIED"
    assert "no member role is configured" in note


def test_member_account_role_is_assumed():
    finding = Finding.from_asff(
        control_finding(
            "EC2.7", "AwsAccount", "AWS::::Account:111122223333", account="111122223333"
        )
    )
    session = Sessions("remediation-member").for_finding(finding)

    identity = session.client("sts").get_caller_identity()
    assert identity["Arn"].startswith("arn:aws:sts::111122223333:assumed-role/remediation-member/")
    assert session.region_name == REGION


def test_long_notes_are_truncated(securityhub):
    finding = Finding.from_asff(control_finding("S3.8", "AwsS3Bucket", "arn:aws:s3:::b"))

    assert _update_finding(securityhub, finding, "NOTIFIED", "x" * 2000)
    assert len(securityhub.last()[1]) == NOTE_LIMIT


def test_dry_run_is_the_default():
    assert Settings.from_env({}).dry_run
    assert Settings.from_env({"DRY_RUN": "no"}).dry_run
    assert not Settings.from_env({"DRY_RUN": "False"}).dry_run
    assert not Settings.from_env({}).quarantine_enabled
