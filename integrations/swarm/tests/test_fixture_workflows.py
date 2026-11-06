"""Runnable examples retain real typed artifact/message evidence in each SDK."""

import pytest

from test_framework_conformance import require_sdk


@pytest.mark.parametrize("framework", ["custom", "langgraph", "autogen"])
def test_pinned_two_agent_fixture_private_lineage_and_child_denial(framework):
    if framework != "custom":
        require_sdk(framework)
    from ordin_swarm.demo import run
    from ordin.schema import validate_named_schema

    report = run(framework)
    assert report["allowed_read_completed"] and report["private_handoff_delivered"]
    assert report["inherited_labels"] == ["secret"] and report["source_flow_violated"]
    assert report["egress_callbacks"] == report["child_callbacks"] == 0
    assert report["denied_reviews"] == 2 and report["post_tool_outcome_linked"]
    assert not report["physical_enforcement"] and report["observed_exfiltration"] == "unknown"
    assert not validate_named_schema("swarm_framework_fixture", report)
