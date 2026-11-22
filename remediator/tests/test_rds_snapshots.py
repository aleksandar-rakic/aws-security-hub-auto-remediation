from __future__ import annotations

import boto3

from conftest import REGION, control_finding, event


def _rds():
    return boto3.client("rds", region_name=REGION)


def _db_snapshot(name: str, shared: list[str], tags: dict[str, str] | None = None) -> str:
    rds = _rds()
    rds.create_db_instance(
        DBInstanceIdentifier=f"{name}-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="admin_user",
        ManageMasterUserPassword=True,
    )
    snapshot = rds.create_db_snapshot(
        DBSnapshotIdentifier=name,
        DBInstanceIdentifier=f"{name}-db",
        Tags=[{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    )["DBSnapshot"]
    if shared:
        rds.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=name, AttributeName="restore", ValuesToAdd=shared
        )
    return snapshot["DBSnapshotArn"]


def _shared(name: str) -> list[str]:
    attributes = _rds().describe_db_snapshot_attributes(DBSnapshotIdentifier=name)[
        "DBSnapshotAttributesResult"
    ]["DBSnapshotAttributes"]
    restore = next((a for a in attributes if a["AttributeName"] == "restore"), {})
    return sorted(restore.get("AttributeValues", []))


def _cluster_snapshot(name: str) -> str:
    rds = _rds()
    rds.create_db_cluster(
        DBClusterIdentifier=f"{name}-cluster",
        Engine="aurora-postgresql",
        MasterUsername="admin_user",
        ManageMasterUserPassword=True,
    )
    snapshot = rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=name, DBClusterIdentifier=f"{name}-cluster"
    )["DBClusterSnapshot"]
    rds.modify_db_cluster_snapshot_attribute(
        DBClusterSnapshotIdentifier=name, AttributeName="restore", ValuesToAdd=["all"]
    )
    return snapshot["DBClusterSnapshotArn"]


def _cluster_shared(name: str) -> list[str]:
    attributes = _rds().describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=name)[
        "DBClusterSnapshotAttributesResult"
    ]["DBClusterSnapshotAttributes"]
    restore = next((a for a in attributes if a["AttributeName"] == "restore"), {})
    return sorted(restore.get("AttributeValues", []))


def test_public_db_snapshot_is_made_private_and_account_sharing_kept(run, securityhub):
    arn = _db_snapshot("nightly", ["all", "111122223333"])

    run(event(control_finding("RDS.1", "AwsRdsDbSnapshot", arn)))

    assert _shared("nightly") == ["111122223333"]
    status, note = securityhub.last()
    assert status == "RESOLVED"
    assert "still shared with 111122223333" in note


def test_public_cluster_snapshot_is_made_private(run, securityhub):
    arn = _cluster_snapshot("aurora-weekly")

    run(event(control_finding("RDS.1", "AwsRdsDbClusterSnapshot", arn)))

    assert _cluster_shared("aurora-weekly") == []
    assert "made cluster-snapshot aurora-weekly private" in securityhub.last()[1]


def test_private_snapshot_is_compliant(run):
    arn = _db_snapshot("internal", [])

    result = run(event(control_finding("RDS.1", "AwsRdsDbSnapshot", arn)))

    assert result["results"][0]["status"] == "compliant"


def test_exempt_snapshot_is_left_alone(run, securityhub):
    arn = _db_snapshot("demo-data", ["all"], tags={"auto-remediation": "skip"})

    run(event(control_finding("RDS.1", "AwsRdsDbSnapshot", arn)))

    assert _shared("demo-data") == ["all"]
    assert securityhub.last()[0] == "NOTIFIED"
