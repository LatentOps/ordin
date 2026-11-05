"""Actual owned kernel execution and explicit outside-boundary bypass evidence."""

from dataclasses import replace
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest

from ordin import (
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.runtime_contract import NetworkCapability, derive_runtime_capability_contract
from ordin.runtime_observation import RuntimeEvidenceSource, RuntimeObservation
from ordin.swarm.linux_backend import ExecutorOutcome, LinuxFileReadBackend


def supported():
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc.syscall(444, None, 0, 1) >= 1


@pytest.fixture
def setup(tmp_path):
    if not supported():
        if os.environ.get("ORDIN_REQUIRE_SWARM_BROKER") == "1":
            pytest.fail("required Linux x86-64 Landlock backend unavailable")
        pytest.skip("owned Linux backend unavailable; no weaker execution fallback")
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir(mode=0o700)
    target = workspace / "data.txt"
    target.write_bytes(b"benign-owned-file\n")
    target.chmod(0o600)
    operator = object()
    semantics = ToolSemanticsRegistry(
        "owned-read",
        "1",
        (
            ToolSemanticRule(
                "read",
                "tool",
                "read_file",
                ("filesystem.read",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    core = Ordin(tool_semantics=semantics)
    action = ToolCallAdapter("fixture").adapt(
        "read_file", {"path": str(target)}, action_id="owned-read"
    )
    contract = derive_runtime_capability_contract(core.review_action(action))
    with tempfile.TemporaryDirectory(prefix="ordin-owned-broker-") as install:
        backend = LinuxFileReadBackend(
            workspace, ("data.txt",), Path(install).resolve(), operator=operator
        )
        compiled = backend.compile(contract)
        assert compiled.enforceable, compiled.as_dict()
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-fixture", "b" * 64)
        try:
            yield backend, compiled.plan, action, source, operator, target
        finally:
            backend.close()


def test_actual_exact_read_has_original_kernel_receipt_and_private_payload(setup):
    backend, plan, action, source, operator, target = setup
    outcome = backend.execute(plan, action, source, operator=operator)
    assert outcome.status == "completed", outcome.as_dict()
    assert outcome.value == target.read_bytes() and outcome.physical_enforcement
    assert backend.verify_outcome(outcome, plan)
    evidence = backend.evidence_record(outcome, operator=operator)
    assert evidence["uid"] > 0 and evidence["seccomp_mode"] == 2 and evidence["landlock_abi"] >= 1
    assert all(value is True for value in evidence["checks"].values())
    assert evidence["limits"]["output_frame_bytes"] == [backend.max_stdout_bytes] * 2
    assert outcome.stdout_bytes > outcome.payload_bytes
    assert outcome.stdout_bytes <= backend.max_stdout_bytes
    assert (
        outcome.observation.outcome == "completed"
        and outcome.observation.action_digest == plan.contract.action_digest
    )
    assert "benign-owned-file" not in json.dumps(outcome.as_dict()) + repr(outcome)
    with pytest.raises(ValueError):
        RuntimeObservation.from_dict(outcome.observation.as_dict())


def test_changed_action_tool_epoch_policy_and_fake_observation_refuse_before_spawn(
    setup, monkeypatch
):
    backend, plan, action, source, operator, target = setup
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("invalid effect forwarded"))
    for changed in (
        replace(action, action_id="other"),
        replace(action, parameters={**action.parameters, "tool": "write_file"}),
        replace(
            action,
            parameters={**action.parameters, "arguments": {"path": str(target.parent / "other")}},
        ),
    ):
        result = backend.execute(plan, changed, source, operator=operator)
        assert result.status != "completed" and not result.physical_enforcement
    changed_plan = replace(plan, policy={**dict(plan.policy), "network": "allow"})
    assert not backend.validate(changed_plan).ok
    fake = ExecutorOutcome(
        "completed",
        "fake",
        plan.contract.action_digest,
        plan.contract.digest,
        plan.policy_digest,
        True,
        "f" * 64,
        1,
        1,
        "e" * 64,
        b"x",
    )
    assert not backend.verify_outcome(fake, plan)


def test_kernel_route_excludes_new_paths_but_raw_host_access_is_uncovered(setup, tmp_path):
    backend, plan, action, source, operator, target = setup
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside-owned-control")
    outside.chmod(0o600)
    assert outside.read_bytes() == b"outside-owned-control"  # Explicit host bypass, outside worker.
    outcome = backend.execute(plan, action, source, operator=operator)
    evidence = backend.evidence_record(outcome, operator=operator)
    assert (
        evidence["checks"]["new_path_read_denied"] and evidence["checks"]["new_path_write_denied"]
    )
    assert (
        evidence["checks"]["network_socket_denied"]
        and evidence["checks"]["process_creation_denied"]
        and evidence["checks"]["executable_launch_denied"]
    )
    other = replace(
        plan.contract,
        contract_id="",
        filesystem=(replace(plan.contract.filesystem[0], path=str(outside)),),
    )
    assert not backend.compile(other).enforceable


def test_symlink_target_and_unrepresented_network_do_not_gain_authority(
    setup, tmp_path, monkeypatch
):
    backend, plan, action, source, operator, target = setup
    network = replace(
        plan.contract,
        contract_id="",
        network=(NetworkCapability("outside.invalid", 443, "tcp", "write"),),
    )
    assert not backend.compile(network).enforceable
    outside = tmp_path / "other.txt"
    outside.write_bytes(b"other")
    target.unlink()
    target.symlink_to(outside)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("symlink effect forwarded"))
    outcome = backend.execute(plan, action, source, operator=operator)
    assert outcome.status != "completed" and not outcome.physical_enforcement


def test_missing_runtime_never_returns_an_enforceable_plan(tmp_path):
    if sys.platform == "linux":
        pytest.skip("unsupported platform fixture")
    backend = LinuxFileReadBackend(
        tmp_path, ("data.txt",), tmp_path / "uncreated", operator=object()
    )
    from tests.assurance.test_delegating_gate import action
    from tests.assurance.test_invariants import SEMANTICS

    contract = derive_runtime_capability_contract(
        Ordin(tool_semantics=SEMANTICS).review_action(action())
    )
    assert not backend.compile(contract).enforceable
    assert not (tmp_path / "uncreated").exists()
