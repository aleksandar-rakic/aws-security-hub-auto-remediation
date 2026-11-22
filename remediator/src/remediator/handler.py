"""Lambda entry point: Security Hub finding events in, fixes and finding updates out.

For each finding in the event:
  * no action for it              -> ignored, the finding is left untouched
  * resource exempt / unreachable -> workflow NOTIFIED with the reason
  * dry run                       -> workflow NOTIFIED with what would have changed
  * fixed or already compliant    -> workflow RESOLVED with what was done
  * action failed                 -> workflow NOTIFIED with the error; the invocation
                                     fails so Lambda retries and then dead-letters it

Moving the finding out of NEW also keeps the EventBridge rule (which matches
Workflow.Status NEW) from firing on it again.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import quarantine
from .actions import Action, Context, Skipped, select_action
from .findings import Finding

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

UPDATED_BY = "security-hub-auto-remediation"
NOTE_LIMIT = 512  # BatchUpdateFindings Note.Text maximum


class RemediationError(Exception):
    """At least one finding in the event could not be remediated."""


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    dry_run: bool = True
    quarantine_enabled: bool = False
    member_role_name: str = ""
    exemption_key: str = "auto-remediation"
    exemption_value: str = "skip"

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> Settings:
        return cls(
            # Anything other than an explicit "false" keeps dry run on.
            dry_run=env.get("DRY_RUN", "true").strip().lower() != "false",
            quarantine_enabled=_flag(env.get("QUARANTINE_ENABLED")),
            member_role_name=env.get("MEMBER_ROLE_NAME", ""),
            exemption_key=env.get("EXEMPTION_TAG_KEY", "auto-remediation"),
            exemption_value=env.get("EXEMPTION_TAG_VALUE", "skip"),
        )


class Sessions:
    """boto3 sessions per (account, region).

    Findings from the Lambda's own account use its own credentials. Findings
    from member accounts (Security Hub delegated administrator setup) assume
    MEMBER_ROLE_NAME in that account; without it they are skipped.
    """

    def __init__(self, member_role_name: str, base: boto3.Session | None = None):
        self._member_role_name = member_role_name
        self._base = base or boto3.Session()
        self._own_account: str | None = None
        self._cache: dict[tuple[str, str], boto3.Session] = {}

    def own_account(self) -> str:
        if self._own_account is None:
            sts = self._base.client("sts")
            self._own_account = sts.get_caller_identity()["Account"]
        return self._own_account

    def for_finding(self, finding: Finding) -> boto3.Session:
        key = (finding.account_id, finding.region)
        if key not in self._cache:
            self._cache[key] = self._open(finding)
        return self._cache[key]

    def _open(self, finding: Finding) -> boto3.Session:
        if finding.account_id == self.own_account():
            return boto3.Session(region_name=finding.region)
        if not self._member_role_name:
            raise Skipped(
                f"resource is in account {finding.account_id} and no member role is configured"
            )
        role_arn = (
            f"arn:{finding.partition}:iam::{finding.account_id}:role/{self._member_role_name}"
        )
        creds = self._base.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=UPDATED_BY)[
            "Credentials"
        ]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=finding.region,
        )


def _select(finding: Finding) -> Action | None:
    if quarantine.applies_to(finding):
        return quarantine.quarantine_instance
    return select_action(finding)


def _update_finding(securityhub: Any, finding: Finding, status: str, note: str) -> bool:
    text = note if len(note) <= NOTE_LIMIT else note[: NOTE_LIMIT - 1] + "…"
    try:
        resp = securityhub.batch_update_findings(
            FindingIdentifiers=[finding.identifier],
            Workflow={"Status": status},
            Note={"Text": text, "UpdatedBy": UPDATED_BY},
        )
    except (ClientError, BotoCoreError):
        log.exception("could not update finding %s", finding.id)
        return False
    if resp.get("UnprocessedFindings"):
        log.error("finding %s not updated: %s", finding.id, resp["UnprocessedFindings"])
        return False
    return True


def _log(event: str, finding: Finding, **fields: Any) -> None:
    log.info(
        json.dumps(
            {
                "event": event,
                "finding": finding.id,
                "control": finding.control_id,
                "account": finding.account_id,
                "region": finding.region,
                "resource": finding.resource_id,
                **fields,
            }
        )
    )


def handle(
    event: dict[str, Any], settings: Settings, sessions: Sessions, securityhub: Any
) -> dict[str, Any]:
    raw_findings = (event.get("detail") or {}).get("findings") or []
    results: list[dict[str, str]] = []
    failures = 0

    for raw in raw_findings:
        finding = Finding.from_asff(raw)
        action = _select(finding)
        if action is None:
            _log("ignored", finding)
            results.append({"finding": finding.id, "status": "ignored"})
            continue

        try:
            ctx = Context(
                session=sessions.for_finding(finding),
                dry_run=settings.dry_run,
                exemption_key=settings.exemption_key,
                exemption_value=settings.exemption_value,
                quarantine_enabled=settings.quarantine_enabled,
            )
            outcome = action(ctx, finding)
        except Skipped as exc:
            status, workflow, note = "skipped", "NOTIFIED", f"Not remediated: {exc}"
        except Exception as exc:  # report it on the finding, then fail the invocation
            log.exception("remediation failed for %s", finding.id)
            failures += 1
            status, workflow = "failed", "NOTIFIED"
            note = f"Automatic remediation failed: {type(exc).__name__}: {exc}"
        else:
            if settings.dry_run:
                status, workflow = "dry_run", "NOTIFIED"
                note = f"Dry run, nothing changed. Would have: {outcome.summary}"
                if not outcome.changed:
                    note = f"Dry run: {outcome.summary}"
            else:
                status, workflow = ("remediated" if outcome.changed else "compliant"), "RESOLVED"
                note = f"Auto-remediated: {outcome.summary}"
                if not outcome.changed:
                    note = f"No change needed: {outcome.summary}"

        if not _update_finding(securityhub, finding, workflow, note):
            failures += 1
        _log(status, finding, workflow=workflow, note=note, dry_run=settings.dry_run)
        results.append({"finding": finding.id, "status": status})

    if failures:
        raise RemediationError(f"{failures} of {len(raw_findings)} finding(s) failed")
    return {"results": results}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    settings = Settings.from_env()
    sessions = Sessions(settings.member_role_name)
    return handle(event, settings, sessions, boto3.client("securityhub"))
