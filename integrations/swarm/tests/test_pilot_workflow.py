"""Actual Linux pilot transitions, separate from elapsed multi-day acceptance."""

import sys

import pytest

pytest.importorskip("ordin_swarm")

from ordin_swarm.pilot_workflow import run_owned_transitions


def test_pilot_workflow_never_uses_an_existing_installation(tmp_path):
    with pytest.raises(ValueError, match="new absolute Linux"):
        run_owned_transitions(tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != "linux", reason="actual original Linux host required")
def test_native_denial_cancel_revocation_restart_and_durable_consumption(tmp_path):
    from tests.test_swarm_broker import require_kernel

    require_kernel()
    result = run_owned_transitions(tmp_path / "pilot")
    assert result["passed"] and len(result["cases"]) == 6
    assert all(case["passed"] for case in result["cases"])
    assert result["duration_seconds"] > 0
    assert not result["execution_authority"]
    assert result["physical_boundary"] == "owned_linux_read_worker"
