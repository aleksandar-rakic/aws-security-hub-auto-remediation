"""The parts of an AWS Security Finding Format (ASFF) record that remediation needs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    id: str
    product_arn: str
    account_id: str
    region: str
    product_name: str
    control_id: str | None
    severity: str
    resource_type: str
    resource_id: str
    raw: dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_asff(cls, finding: dict[str, Any]) -> Finding:
        resources = finding.get("Resources") or [{}]
        resource = resources[0]
        return cls(
            id=finding["Id"],
            product_arn=finding["ProductArn"],
            account_id=finding["AwsAccountId"],
            region=finding.get("Region") or finding["ProductArn"].split(":")[3],
            product_name=finding.get("ProductName", ""),
            control_id=_control_id(finding),
            severity=(finding.get("Severity") or {}).get("Label", ""),
            resource_type=resource.get("Type", ""),
            resource_id=resource.get("Id", ""),
            raw=finding,
        )

    @property
    def partition(self) -> str:
        return self.product_arn.split(":")[1]

    @property
    def identifier(self) -> dict[str, str]:
        """The key BatchUpdateFindings expects for this finding."""
        return {"Id": self.id, "ProductArn": self.product_arn}

    @property
    def resource_name(self) -> str:
        """Last segment of the resource ARN: bucket name, sg-…, i-…, key id."""
        rid = self.resource_id
        if ":::" in rid:  # arn:aws:s3:::bucket
            return rid.split(":::", 1)[1]
        return rid.rsplit("/", 1)[-1]


def _control_id(finding: dict[str, Any]) -> str | None:
    # Consolidated control findings carry SecurityControlId; standard-specific
    # findings from before consolidation only have ProductFields.ControlId.
    compliance = finding.get("Compliance") or {}
    if compliance.get("SecurityControlId"):
        return compliance["SecurityControlId"]
    return (finding.get("ProductFields") or {}).get("ControlId")
