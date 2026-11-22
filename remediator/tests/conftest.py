from __future__ import annotations

from typing import Any

import boto3
import pytest
from moto import mock_aws

from remediator.handler import Sessions, Settings, handle

ACCOUNT = "123456789012"  # moto's default account
REGION = "eu-central-1"


@pytest.fixture(autouse=True)
def aws(monkeypatch):
    for name in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield


class FakeSecurityHub:
    """Records BatchUpdateFindings calls; moto does not implement that API."""

    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []

    def batch_update_findings(self, **kwargs: Any) -> dict[str, Any]:
        self.updates.append(kwargs)
        return {"ProcessedFindings": kwargs["FindingIdentifiers"], "UnprocessedFindings": []}

    def last(self) -> tuple[str, str]:
        update = self.updates[-1]
        return update["Workflow"]["Status"], update["Note"]["Text"]


@pytest.fixture
def securityhub() -> FakeSecurityHub:
    return FakeSecurityHub()


@pytest.fixture
def session() -> boto3.Session:
    return boto3.Session(region_name=REGION)


def control_finding(
    control_id: str,
    resource_type: str,
    resource_id: str,
    account: str = ACCOUNT,
    legacy: bool = False,
) -> dict[str, Any]:
    product_arn = f"arn:aws:securityhub:{REGION}::product/aws/securityhub"
    finding: dict[str, Any] = {
        "Id": f"arn:aws:securityhub:{REGION}:{account}:security-control/{control_id}/finding/1",
        "ProductArn": product_arn,
        "ProductName": "Security Hub",
        "AwsAccountId": account,
        "Region": REGION,
        "Severity": {"Label": "HIGH"},
        "Compliance": {"Status": "FAILED"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "Resources": [{"Type": resource_type, "Id": resource_id, "Region": REGION}],
    }
    if legacy:
        finding["ProductFields"] = {"ControlId": control_id}
    else:
        finding["Compliance"]["SecurityControlId"] = control_id
    return finding


def event(*findings: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "detail": {"findings": list(findings)},
    }


@pytest.fixture
def run(securityhub):
    def _run(evt: dict[str, Any], **settings: Any) -> dict[str, Any]:
        settings.setdefault("dry_run", False)
        cfg = Settings(**settings)
        return handle(evt, cfg, Sessions(cfg.member_role_name), securityhub)

    return _run
