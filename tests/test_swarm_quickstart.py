"""Offline quickstart is a host fixture and never claims OS enforcement."""

from pathlib import Path
import json
import socket
import sys

from ordin.schema import validate_named_schema


def test_two_agent_quickstart_preserves_modes_privacy_and_explicit_physical_gap(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
    before_connect = socket.socket.connect
    before_modules = set(sys.modules)
    from ordin_swarm.quickstart import run

    report = run()
    assert not validate_named_schema("swarm_quickstart", report)
    assert report["observe_only"]["callbacks_invoked"] == 0
    assert not report["shadow"]["execution_performed"]
    for stage in (report["observe_only"], report["shadow"]):
        assert [(row["case_id"], row["disposition"]) for row in stage["reviews"]] == [
            ("benign", "execute"),
            ("unsafe", "deny"),
            ("benign", "execute"),
            ("unsafe", "deny"),
        ]
    assert report["mediated"]["private_handoff_delivered"]
    assert report["mediated"]["egress_callbacks"] == report["mediated"]["child_callbacks"] == 0
    assert (
        report["runtime_enforcement"] == "not_evaluated" and report["physical_enforcement"] is False
    )
    assert set(report["uncovered_paths"]) == {
        "direct_host_tools",
        "raw_host_network",
        "existing_credentials",
        "unwrapped_processes",
    }
    assert report["execution_authority"] is False
    assert socket.socket.connect is before_connect
    assert not any(
        name.startswith(("crewai", "langgraph", "autogen_core"))
        for name in set(sys.modules) - before_modules
    )
    serialized = json.dumps(report)
    assert str(Path.home()) not in serialized
