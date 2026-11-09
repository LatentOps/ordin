"""Evaluation summaries retain failures and never imply model/agent confinement."""

import sys

import pytest

from ordin_swarm.host_evaluation import _summary, evaluation_profile, run_evaluation
from ordin_swarm.host_profiles import ToolHostProfile


def test_evaluation_profile_has_only_exact_owned_offline_network_and_actor_scopes(tmp_path):
    profile = ToolHostProfile.from_dict(
        evaluation_profile(tmp_path, reference_port=9443), configuration_root=tmp_path
    )
    assert profile.actor("reader").write_files == ()
    assert profile.actor("writer").read_files == ()
    assert profile.http_routes[0].addresses == ("127.0.0.1",)
    assert profile.http_routes[0].response_label == "public"


def test_evaluation_failures_are_counted_without_claiming_broader_security():
    cases = [
        {"case_id": "allowed_read", "kind": "benign", "passed": False, "duration_ms": 1.0},
        {"case_id": "forbidden_write", "kind": "attack", "passed": False, "duration_ms": 2.0},
    ]
    report = _summary(cases, elapsed=3.0, profile_digest="a" * 64)
    assert not report["passed"]
    assert report["false_blocks"] == 1 and report["false_allows"] == 1
    assert report["hosted_models_used"] is False
    assert report["client_process_confinement"] == "not_established"
    assert report["complete"] is False and report["fixed_tests_exercised"] is False
    unavailable = _summary(cases[:1], elapsed=1.0, profile_digest="a" * 64)
    assert unavailable["attack_total"] == unavailable["false_allows"] == 0
    assert unavailable["passed"] is False


@pytest.mark.skipif(
    sys.platform != "linux", reason="actual owned HTTP/write and TLS host boundary required"
)
@pytest.mark.parametrize("enhanced", [False, True])
def test_actual_offline_two_agent_workflow_and_attack_suite(tmp_path, monkeypatch, enhanced):
    from test_tool_host_deployment import _CONNECT, _CREATE_CONNECTION
    import socket

    # Both ephemeral listeners are owned by run_evaluation; constrain all test
    # connections to IPv4 loopback rather than opening model/telemetry access.
    def loopback(connection, address):
        if type(address) is not tuple or len(address) != 2 or address[0] != "127.0.0.1":
            raise AssertionError("evaluation contacted an external endpoint")
        return _CONNECT(connection, address)

    monkeypatch.setattr(socket.socket, "connect", loopback)
    monkeypatch.setattr(socket, "create_connection", _CREATE_CONNECTION)
    result = run_evaluation(tmp_path / "evaluation", with_tests=enhanced, protected=enhanced)
    assert result["passed"] is True, result
    assert result["benign_total"] >= 5 and result["attack_total"] >= 8
    assert result["false_blocks"] == result["false_allows"] == 0
    assert result["fixed_tests_exercised"] is enhanced
    assert result["protected_fixture"] == ("kernel_enforced" if enhanced else "not_requested")
