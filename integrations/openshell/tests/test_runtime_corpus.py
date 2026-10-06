import json
import importlib.util
import copy
import shlex
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest

from ordin import (
    ActionEnvelope,
    ActionHistory,
    AgentGate,
    IntegrationSession,
    Ordin,
    RuntimeEvidenceSource,
    RuntimeObservationHistory,
    ObservedResource,
    SessionIdentity,
    derive_runtime_capability_contract,
)
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin.runtime_reasoning import current_runtime_signals
from ordin.session import configuration_digest
from ordin_openshell.corpus import evaluate_runtime_corpus
from test_compiler import compile


ROOT = Path(__file__).resolve().parents[3]


def test_demo_refuses_broader_fixtures_before_running_negative_probes():
    spec = importlib.util.spec_from_file_location(
        "runtime_demo", ROOT / "scripts/run_openshell_runtime_demo.py"
    )
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    policy = compile().plan.as_dict()["policy"]
    fs = {"read_only": ["/readonly"], "read_write": ["/tmp"]}
    demo.validate_demo_fixtures(policy, fs)
    wider = copy.deepcopy(policy)
    endpoint = next(iter(wider["network_policies"].values()))["endpoints"][0]
    endpoint["rules"].append(
        {"allow": {"method": "POST", "path": "/repos/LatentOps/ordin/issues/37"}}
    )
    with pytest.raises(ValueError, match="read_only_network"):
        demo.validate_demo_fixtures(wider, fs)
    with pytest.raises(ValueError, match="read_only_filesystem"):
        demo.validate_demo_fixtures(policy, {"read_only": ["/readonly"], "read_write": ["/"]})


def test_filesystem_demo_attaches_probe_evidence_to_the_exact_executed_invocation(
    monkeypatch, tmp_path
):
    spec = importlib.util.spec_from_file_location(
        "runtime_demo_binding", ROOT / "scripts/run_openshell_runtime_demo.py"
    )
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    policy = compile().plan.as_dict()["policy"]
    policy["filesystem_policy"]["read_only"].append("/readonly")
    snapshot = SimpleNamespace(policy=policy, sandbox_id="sandbox", policy_digest="b" * 64)
    monkeypatch.setattr(demo, "read_runtime_policy", lambda *args: snapshot)
    invocations = []

    def execute(argv, **kwargs):
        program = argv[argv.index("--") + 1 :]
        invocations.append(program)
        if program[0] == "/usr/bin/cat":
            body, code = "non-secret fixture", 0
        elif program[0] == "/usr/bin/python3":
            body, code = (
                json.dumps(
                    {
                        "euid": 1000,
                        "file_uid": 1000,
                        "mode": 0o666,
                        "read_succeeded": True,
                        "write_control_succeeded": True,
                        "protected_write_denied": True,
                    }
                ),
                0,
            )
        elif program[-1] == "https://example.com/":
            body, code = "", 7
        elif "POST" in program:
            body, code = '{"error":"policy_denied"}', 0
        else:
            body, code = '{"number":37}', 0
        return subprocess.CompletedProcess(argv, code, body, "")

    monkeypatch.setattr(demo.subprocess, "run", execute)
    report = demo.run(
        SimpleNamespace(
            sandbox="network",
            filesystem_sandbox="filesystem",
            openshell="/trusted/openshell",
            workspace="default",
            gateway_endpoint="http://127.0.0.1:18780",
            correlation_db=str(tmp_path / "correlation.db"),
            ocsf_directory=str(tmp_path),
        )
    )
    evidence = next(r for r in report["records"] if r["name"] == "filesystem_evidence_return")
    program = next(p for p in invocations if p[0] == "/usr/bin/python3")
    actual_action = ActionEnvelope.shell(shlex.join(program), action_id="fs-negative-probe")
    assert evidence["passed"]
    assert (
        evidence["action_digest"]
        == derive_runtime_capability_contract(Ordin().review_action(actual_action)).action_digest
    )
    assert evidence["contract_id"] != evidence["read_contract_id"]
    assert ["/usr/bin/cat", "/readonly/input.txt"] in invocations
    assert not report["passed"]  # Mock output cannot replace actual correlated network events.


def test_demo_network_attribution_uses_exact_target_before_http_method():
    spec = importlib.util.spec_from_file_location(
        "runtime_demo_targets", ROOT / "scripts/run_openshell_runtime_demo.py"
    )
    assert spec is not None and spec.loader is not None
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert (
        demo.probe_identity({"host": "example.com", "port": 443, "method": "GET", "path": "/"})
        == "unrelated_host"
    )
    assert (
        demo.probe_identity(
            {"host": "api.github.com", "port": 443, "method": "GET", "path": "/other"}
        )
        is None
    )
    assert (
        demo.probe_identity(
            {
                "host": "api.github.com",
                "port": 443,
                "method": "GET",
                "path": "/repos/LatentOps/ordin/issues/37",
            }
        )
        == "get"
    )


def test_required_versioned_runtime_corpus_passes_all_named_adversaries():
    data = json.loads((ROOT / "benchmarks/runtime_enforcement.json").read_text())
    report = evaluate_runtime_corpus(data)
    assert report["cases"] == 13 and report["failed"] == 0, report
    assert len({r["id"] for r in report["results"]}) == 13
    assert all(r["evidence"] for r in report["results"])


def test_actual_http_metadata_can_match_reviewed_url_without_host_only_inference():
    engine = Ordin()
    action = ActionEnvelope.shell(
        "curl --disable --request GET https://api.github.com/rate_limit", action_id="request"
    )
    review = engine.review_action(action)
    contract = derive_runtime_capability_contract(review)
    source = RuntimeEvidenceSource("openshell", "a" * 64, "sandbox", "b" * 64)

    def event(identity, port=443, path="/rate_limit"):
        return source.observe(
            contract,
            observation_id=identity,
            trust="backend_enforced",
            enforcement_point="network",
            outcome="denied",
            operation="http.request",
            reason_code="policy_denied",
            resources=(ObservedResource("host", "api.github.com"),),
            metadata={"host": "api.github.com", "port": port, "path": path, "method": "GET"},
        )

    events = (event("one"), event("two"))
    runtime = RuntimeObservationHistory(events, (contract,))
    strengthened = engine.review_action(
        action, history=ActionHistory((action,)), runtime_observations=runtime
    )
    assert "trajectory_policy_bypass_attempt" in strengthened.trajectory_categories
    for differing in (event("other-port", port=80), event("other-path", path="/other")):
        assert "signal:runtime-boundary-retry" not in current_runtime_signals(
            review, {"prior": (events[0], differing)}
        )
    incomplete = source.observe(
        contract,
        observation_id="incomplete",
        trust="backend_enforced",
        enforcement_point="network",
        outcome="denied",
        operation="network.connect",
        reason_code="policy_denied",
        resources=(ObservedResource("host", "api.github.com"),),
    )
    assert "signal:runtime-boundary-retry" not in current_runtime_signals(
        review, {"prior": (events[0], incomplete)}
    )
    contradictory = source.observe(
        contract,
        observation_id="contradictory",
        trust="backend_enforced",
        enforcement_point="network",
        outcome="denied",
        operation="http.request",
        reason_code="policy_denied",
        resources=(ObservedResource("url", "https://api.github.com/rate_limit"),),
        metadata={"host": "api.github.com", "port": 443, "path": "/other", "method": "GET"},
    )
    assert "signal:runtime-boundary-retry" not in current_runtime_signals(
        review, {"prior": (events[0], contradictory)}
    )


def test_host_profile_is_in_session_identity_and_retained_original_contract():
    profile = RuntimeRequirementProfile(
        "deployment",
        filesystem=(
            FilesystemCapability("read", "/usr", "prefix"),
            FilesystemCapability("execute", "/usr", "prefix"),
        ),
        executable_bindings={"curl": "/usr/bin/curl"},
        spawn_children=True,
    )
    gate = AgentGate(Ordin(runtime_requirements=profile))
    assert configuration_digest(gate) != configuration_digest(AgentGate())
    session = IntegrationSession(SessionIdentity("host", "profile-session"), gate)
    source = RuntimeEvidenceSource("openshell", session.runtime_session_digest, "sandbox", "b" * 64)
    session.bind_runtime_source(source)
    action = ActionEnvelope.shell(
        "curl --disable --request GET https://api.github.com/rate_limit", action_id="get"
    )
    decision = session.evaluate(action)
    contract = session.runtime_contract("get")
    assert contract == derive_runtime_capability_contract(decision.review)
    assert contract.process.spawn_children is True and contract.process.executables == (
        "/usr/bin/curl",
    )
    assert set(contract.filesystem) == set(profile.filesystem)
    with pytest.raises(ValueError):
        Ordin(runtime_requirements={"spawn_children": True})
