"""Optional behavioral risk cannot borrow an original core human approval."""

from pathlib import Path

import pytest

pytest.importorskip("ordin.swarm.risk_signals")

from ordin.swarm.corpus_controls import run_control


@pytest.mark.parametrize(
    "scenario",
    (
        "approval-risk-escalation",
        "approval-risk-deny",
        "approval-risk-missing",
        "approval-risk-missing-ignore",
    ),
)
def test_original_core_approval_joins_independent_risk_restrictively(tmp_path: Path, scenario):
    result = run_control(scenario, agents=3, seed=276, workspace=tmp_path / "risk")
    assert all(result["checks"].values())
    assert result["actual"] == ("execute" if scenario.endswith("-ignore") else "deny")
