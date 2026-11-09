"""The aggregate retains real fixed-runner custody and never approves a warning."""

from copy import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest

from ordin import ToolCallAdapter
from ordin._runtime_json import digest
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.swarm.confined_tests import TestRoute, build_python_runtime_catalog
from ordin.swarm.linux_backend import KernelJob
from ordin.swarm.owned_tools import LinuxOwnedToolsBackend
from ordin.swarm._owned_test_output import bounded_test_value
from ordin.swarm._owned_protocol import wire
from tests.test_swarm_confined_tests import contract, kernel_only


@pytest.mark.parametrize("text", ["ordinary diagnostic", "\x00" * 8192, "π" * 8192])
def test_diagnostic_delivery_bounds_preserve_untrusted_exit_and_snapshot(text):
    value = wire(
        {
            "exit_code": 1,
            "output": text,
            "output_truncated": False,
            "output_trust": "untrusted_test_diagnostic",
            "test_correctness_verified": False,
            "snapshot_digest": "a" * 64,
        }
    )
    result = bounded_test_value(value, 16384)
    decoded = json.loads(result)
    assert len(result) <= 16384 and decoded["exit_code"] == 1
    assert decoded["snapshot_digest"] == "a" * 64 and decoded["test_correctness_verified"] is False
    assert text.startswith(decoded["output"])
    assert decoded["output_truncated"] is (decoded["output"] != text)


def test_child_cannot_promote_diagnostics_or_supply_unbounded_json():
    with pytest.raises(ValueError):
        bounded_test_value(b"x" * 65537, 16384)
    with pytest.raises(ValueError):
        bounded_test_value(wire({"test_correctness_verified": True}), 16384)


def configured_backend(tmp_path, text="def test_pass():\n    assert 2 + 2 == 4\n"):
    kernel_only()
    operator = object()
    project, runtime, workspace = (
        tmp_path / value for value in ("project", "runtime", "workspace")
    )
    for path in (project, runtime, workspace):
        path.mkdir(mode=0o700)
    (project / "test_owned.py").write_text(text, encoding="utf-8")
    catalog = build_python_runtime_catalog(runtime, operator=operator)
    route = TestRoute("unit", project, ("test_owned.py",), catalog)
    uid, gid = LinuxOwnedToolsBackend.worker_identity()
    if os.geteuid() == 0:
        os.chown(workspace, uid, gid)
    installation = tempfile.TemporaryDirectory(prefix="ordin-owned-tests-")
    backend = LinuxOwnedToolsBackend(
        workspace,
        ("report.txt",),
        Path(installation.name),
        operator=operator,
        initialize=True,
        test_routes=(route,),
        max_payload_bytes=16384,
    )
    action = ToolCallAdapter("ordin-owned").adapt(
        "run_tests", {"test_id": "unit"}, action_id="owned-test"
    )
    return operator, backend, route, action, installation


def test_original_confined_runner_result_is_aggregated_and_bound_to_its_job(tmp_path):
    operator, backend, route, action, install = configured_backend(tmp_path)
    try:
        action = backend.prepare_action(action, operator=operator)
        assert backend.prepare_action(action, operator=operator) is action
        complete = contract(action, route)  # Explicit protected-owner test fixture only.
        compiled = backend.compile_action(action, complete)
        assert compiled.enforceable, compiled.as_dict()
        plan = compiled.plan
        assert backend.compile_action(action, complete).plan is plan
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-fixed-test", "b" * 64)
        job = backend.create_job(plan, operator=operator)
        result = backend.execute(plan, action, source, operator=operator, job=job)
        if (
            result.status == "unsupported"
            and os.environ.get("ORDIN_REQUIRED_PROTECTED_PROCESS") != "1"
        ):
            pytest.skip("required mount/Landlock/seccomp test profile unavailable; no fallback")
        assert result.status == "completed" and result.physical_enforcement, result.as_dict()
        assert result.backend == backend.name and backend.verify_outcome(result, plan)
        assert not backend.verify_outcome(copy(result), plan)
        assert backend.job_status(job, operator=operator) == "finished"
        output = json.loads(result.value)
        assert output["exit_code"] == 0 and output["test_correctness_verified"] is False
        assert output["output_trust"] == "untrusted_test_diagnostic" and len(result.value) <= 16384
        assert output["snapshot_digest"] == action.parameters["host_test_snapshot"]["digest"]
        evidence = backend.evidence_record(result, operator=operator)
        assert evidence["test_correctness_verified"] is False and evidence[
            "original_test_plan"
        ].startswith("ep:")
        with pytest.raises(ValueError):
            backend.execute(plan, action, source, operator=operator, job=job)
    finally:
        backend.close()
        install.cleanup()


def test_warning_and_changed_snapshot_never_reach_an_owned_process(tmp_path, monkeypatch):
    operator, backend, route, action, install = configured_backend(tmp_path)
    try:
        action = backend.prepare_action(action, operator=operator)
        warning = contract(action, route, decision="warn")
        assert warning.grant_state == "requires_approval"
        assert not backend.compile_action(action, warning).enforceable
        complete = contract(action, route)
        plan = backend.compile_action(action, complete).plan
        assert plan is not None and not backend.validate(copy(plan)).ok
        (route.project_root / "test_owned.py").write_text(
            "def test_changed():\n    assert False\n", encoding="utf-8"
        )
        assert not backend.validate(plan).ok
        monkeypatch.setattr(
            "subprocess.Popen", lambda *a, **k: pytest.fail("changed source was forwarded")
        )
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-fixed-test", "b" * 64)
        with pytest.raises(ValueError):
            backend.execute(plan, action, source, operator=operator)
        with pytest.raises(ValueError):
            backend.prepare_action(action, operator=operator)
    finally:
        backend.close()
        install.cleanup()


def test_original_test_stop_refuses_foreign_handle_and_prevents_start(tmp_path, monkeypatch):
    operator, backend, route, action, install = configured_backend(tmp_path)
    try:
        action = backend.prepare_action(action, operator=operator)
        plan = backend.compile_action(action, contract(action, route)).plan
        job = backend.create_job(plan, operator=operator)
        with pytest.raises(ValueError):
            backend.request_stop(KernelJob(job.job_id), operator=operator)
        assert backend.request_stop(job, operator=operator) == "canceled"
        monkeypatch.setattr(
            "subprocess.Popen", lambda *a, **k: pytest.fail("stopped test was forwarded")
        )
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-fixed-test", "b" * 64)
        with pytest.raises(ValueError):
            backend.execute(plan, action, source, operator=operator, job=job)
    finally:
        backend.close()
        install.cleanup()
