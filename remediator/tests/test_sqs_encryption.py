from __future__ import annotations

import boto3

from conftest import ACCOUNT, REGION, control_finding, event


def _queue(name: str, attributes: dict[str, str] | None = None, tags=None) -> tuple[str, str]:
    sqs = boto3.client("sqs", region_name=REGION)
    url = sqs.create_queue(QueueName=name, Attributes=attributes or {}, tags=tags or {})["QueueUrl"]
    return url, f"arn:aws:sqs:{REGION}:{ACCOUNT}:{name}"


def _attributes(url: str) -> dict[str, str]:
    sqs = boto3.client("sqs", region_name=REGION)
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]


def test_unencrypted_queue_gets_sse_sqs(run, securityhub):
    url, arn = _queue("orders", {"SqsManagedSseEnabled": "false"})

    run(event(control_finding("SQS.1", "AwsSqsQueue", arn)))

    assert _attributes(url)["SqsManagedSseEnabled"] == "true"
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "queue orders" in note


def test_queue_on_a_kms_key_is_left_alone(run, securityhub):
    url, arn = _queue("payments", {"KmsMasterKeyId": "alias/payments"})

    result = run(event(control_finding("SQS.1", "AwsSqsQueue", arn)))

    assert result["results"][0]["status"] == "compliant"
    assert _attributes(url)["KmsMasterKeyId"] == "alias/payments"


def test_exempt_queue_is_left_alone(run, securityhub):
    url, arn = _queue("legacy", {"SqsManagedSseEnabled": "false"}, {"auto-remediation": "skip"})

    run(event(control_finding("SQS.1", "AwsSqsQueue", arn)))

    assert _attributes(url)["SqsManagedSseEnabled"] == "false"
    assert securityhub.last()[0] == "NOTIFIED"


def test_fifo_queue_names_are_handled(run, securityhub):
    url, arn = _queue("events.fifo", {"FifoQueue": "true", "SqsManagedSseEnabled": "false"})

    run(event(control_finding("SQS.1", "AwsSqsQueue", arn)))

    assert _attributes(url)["SqsManagedSseEnabled"] == "true"
