from __future__ import annotations

import json

import boto3

from conftest import REGION, control_finding, event


def _bucket(name: str, policy: dict | None = None) -> str:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    if policy:
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    return f"arn:aws:s3:::{name}"


def _statements(name: str) -> list[dict]:
    s3 = boto3.client("s3", region_name=REGION)
    return json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])["Statement"]


def test_tls_is_required_on_a_bucket_without_policy(run, securityhub):
    arn = _bucket("no-policy")

    run(event(control_finding("S3.5", "AwsS3Bucket", arn)))

    (statement,) = _statements("no-policy")
    assert statement["Effect"] == "Deny"
    assert statement["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert statement["Resource"] == [arn, f"{arn}/*"]
    assert securityhub.last()[0] == "RESOLVED"


def test_existing_statements_are_kept(run, securityhub):
    reader = {
        "Sid": "CloudFrontRead",
        "Effect": "Allow",
        "Principal": {"Service": "cloudfront.amazonaws.com"},
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::site/*",
    }
    arn = _bucket("site", {"Version": "2012-10-17", "Statement": [reader]})

    run(event(control_finding("S3.5", "AwsS3Bucket", arn)))

    statements = _statements("site")
    assert [s["Sid"] for s in statements] == ["CloudFrontRead", "DenyInsecureTransport"]
    assert statements[0] == reader
    assert "keeping its 1 existing statement(s)" in securityhub.last()[1]


def test_an_equivalent_deny_written_differently_counts(run, securityhub):
    deny = {
        "Effect": "Deny",
        "Principal": {"AWS": "*"},
        "Action": "s3:*",
        "Resource": ["arn:aws:s3:::strict", "arn:aws:s3:::strict/*"],
        "Condition": {"Bool": {"aws:securetransport": ["false"]}},
    }
    arn = _bucket("strict", {"Version": "2012-10-17", "Statement": [deny]})

    result = run(event(control_finding("S3.5", "AwsS3Bucket", arn)))

    assert result["results"][0]["status"] == "compliant"
    assert len(_statements("strict")) == 1


def test_dry_run_leaves_the_policy_alone(run, securityhub):
    arn = _bucket("draft")

    run(event(control_finding("S3.5", "AwsS3Bucket", arn)), dry_run=True)

    s3 = boto3.client("s3", region_name=REGION)
    try:
        s3.get_bucket_policy(Bucket="draft")
    except s3.exceptions.ClientError as exc:
        assert exc.response["Error"]["Code"] == "NoSuchBucketPolicy"
    else:
        raise AssertionError("dry run wrote a bucket policy")
    assert securityhub.last()[0] == "NOTIFIED"
