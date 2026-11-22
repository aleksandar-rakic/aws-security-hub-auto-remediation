"""The Terraform rule must match exactly the controls the Lambda can fix."""

from __future__ import annotations

import re
from pathlib import Path

from remediator.actions import CONTROL_ACTIONS

CONTROLS_TF = Path(__file__).parents[2] / "terraform" / "remediation" / "controls.tf"


def test_terraform_supported_controls_match_the_lambda():
    text = CONTROLS_TF.read_text()
    block = re.search(r"supported_controls\s*=\s*\[(.*?)\]", text, re.S)
    assert block, f"supported_controls not found in {CONTROLS_TF}"
    terraform = re.findall(r'"([^"]+)"', block.group(1))

    assert len(terraform) == len(set(terraform)), "duplicate control in controls.tf"
    assert set(terraform) == set(CONTROL_ACTIONS)
