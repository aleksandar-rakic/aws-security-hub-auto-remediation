from __future__ import annotations

import boto3

from conftest import REGION, control_finding, event


def _repository(name: str, scan: bool = False, tags: dict[str, str] | None = None) -> str:
    ecr = boto3.client("ecr", region_name=REGION)
    repository = ecr.create_repository(
        repositoryName=name,
        imageScanningConfiguration={"scanOnPush": scan},
        tags=[{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    )["repository"]
    return repository["repositoryArn"]


def _scans(name: str) -> bool:
    ecr = boto3.client("ecr", region_name=REGION)
    (repository,) = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    return repository["imageScanningConfiguration"]["scanOnPush"]


def test_scan_on_push_is_turned_on_for_nested_names(run, securityhub):
    arn = _repository("payments/api")

    run(event(control_finding("ECR.1", "AwsEcrRepository", arn)))

    assert _scans("payments/api")
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "repository payments/api" in note


def test_repository_already_scanning_is_compliant(run):
    arn = _repository("web", scan=True)

    result = run(event(control_finding("ECR.1", "AwsEcrRepository", arn)))

    assert result["results"][0]["status"] == "compliant"


def test_exempt_repository_is_left_alone(run, securityhub):
    arn = _repository("scratch", tags={"auto-remediation": "skip"})

    run(event(control_finding("ECR.1", "AwsEcrRepository", arn)))

    assert not _scans("scratch")
    assert securityhub.last()[0] == "NOTIFIED"
