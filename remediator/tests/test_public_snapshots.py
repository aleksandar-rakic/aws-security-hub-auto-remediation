from __future__ import annotations

import boto3

from conftest import ACCOUNT, REGION, control_finding, event


def _snapshot(public: bool, tags: dict[str, str] | None = None, shared_with: str = "") -> str:
    ec2 = boto3.client("ec2", region_name=REGION)
    volume = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    spec = {}
    if tags:
        spec["TagSpecifications"] = [
            {"ResourceType": "snapshot", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        ]
    snapshot = ec2.create_snapshot(VolumeId=volume, **spec)["SnapshotId"]
    if public:
        ec2.modify_snapshot_attribute(
            SnapshotId=snapshot,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )
    if shared_with:
        ec2.modify_snapshot_attribute(
            SnapshotId=snapshot,
            Attribute="createVolumePermission",
            OperationType="add",
            UserIds=[shared_with],
        )
    return snapshot


def _permissions(snapshot: str) -> list[dict]:
    ec2 = boto3.client("ec2", region_name=REGION)
    return ec2.describe_snapshot_attribute(SnapshotId=snapshot, Attribute="createVolumePermission")[
        "CreateVolumePermissions"
    ]


def _finding() -> dict:
    return control_finding("EC2.1", "AwsAccount", f"AWS::::Account:{ACCOUNT}")


def test_public_snapshots_are_made_private_and_account_sharing_is_kept(run, securityhub):
    shared = _snapshot(public=True, shared_with="111122223333")
    plain = _snapshot(public=True)
    private = _snapshot(public=False)

    run(event(_finding()))

    assert _permissions(shared) == [{"UserId": "111122223333"}]
    assert _permissions(plain) == []
    assert _permissions(private) == []
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "made 2 snapshot(s) private" in note


def test_exempt_snapshot_stays_public(run, securityhub):
    exempt = _snapshot(public=True, tags={"auto-remediation": "skip"})
    other = _snapshot(public=True)

    run(event(_finding()))

    assert _permissions(exempt) == [{"Group": "all"}]
    assert _permissions(other) == []
    assert f"left exempt {exempt} public" in securityhub.last()[1]


def test_only_exempt_snapshots_public_is_a_skip(run, securityhub):
    _snapshot(public=True, tags={"auto-remediation": "skip"})

    result = run(event(_finding()))

    assert result["results"][0]["status"] == "skipped"
    assert securityhub.last()[0] == "NOTIFIED"


def test_no_public_snapshots_is_compliant(run, securityhub):
    _snapshot(public=False)

    result = run(event(_finding()))

    assert result["results"][0]["status"] == "compliant"
