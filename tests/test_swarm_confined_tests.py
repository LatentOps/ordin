"""Fixed test execution binds sealed bytes and original kernel receipts."""

from copy import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from ordin._runtime_json import digest
from ordin.adapters import ToolCallAdapter
from ordin.runtime_contract import (
    FilesystemCapability,
    PrivilegeCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    ToolCapability,
)
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.swarm.confined_tests import (
    LinuxConfinedTestRunner,
    PythonRuntimeCatalog,
    TestRoute,
    _capture,
    _tree_digest,
    build_python_runtime_catalog,
)
from ordin.swarm.managed_process import ProtectedProcessLimits


def setup(tmp_path, text="def test_ok():\n    assert 1 + 1 == 2\n", *, portable=False, limits=None):
    operator = object()
    project, runtime, install = (tmp_path / value for value in ("project", "runtime", "install"))
    for path in (project, runtime, install):
        path.mkdir(mode=0o700)
    (project / "test_sample.py").write_text(text, encoding="utf-8")
    if portable:
        catalog = PythonRuntimeCatalog(
            runtime, "a" * 64, Path(sys.executable).resolve(), "b" * 64, "/fixed-stdlib", "fixed"
        )
    else:
        catalog = build_python_runtime_catalog(runtime, operator=operator)
    route = TestRoute("unit", project, ("test_sample.py",), catalog)
    kwargs = {} if limits is None else {"limits": limits}
    runner = LinuxConfinedTestRunner((route,), install, operator=operator, **kwargs)
    action = ToolCallAdapter("ordin-owned").adapt(
        "run_tests", {"test_id": "unit"}, action_id="host-1"
    )
    return operator, runner, route, action


def contract(action, route, *, decision="allow"):
    return RuntimeCapabilityContract(
        action.action_id,
        digest(action.as_dict()),
        decision,
        "low",
        filesystem=tuple(
            sorted(
                (
                    FilesystemCapability("read", str(route.project_root), "prefix"),
                    FilesystemCapability("read", str(route.runtime.root), "prefix"),
                ),
                key=lambda value: value.path,
            )
        ),
        tools=(ToolCapability("ordin-owned", None, "run_tests"),),
        process=ProcessCapability(True, (str(route.runtime.interpreter),), False),
        privilege=PrivilegeCapability(False),
        source={
            "kind": "tool",
            "adapter": "fixed_test",
            "operation": "call",
            "effects": ["code.execute"],
            "provenance_digest": None,
        },
    )


def prepare(runner, route, action, operator, decision="allow"):
    action = runner.prepare_action(action, operator=operator)
    compiled = runner.compile_action(action, contract(action, route, decision=decision))
    assert compiled.enforceable and compiled.plan is not None
    plan = compiled.plan
    source = RuntimeEvidenceSource(runner.name, "c" * 64, "confined-test", plan.policy_digest)
    return action, plan, source


def kernel_only():
    if sys.platform != "linux" or os.geteuid() != 0:
        if os.environ.get("ORDIN_REQUIRED_PROTECTED_PROCESS") == "1":
            pytest.fail("required fixed test runner needs qualified privileged Linux")
        pytest.skip("fixed test runner requires privileged Linux kernel controls")


def assert_kernel_result(runner, plan, result):
    if result.status == "unsupported" and os.environ.get("ORDIN_REQUIRED_PROTECTED_PROCESS") != "1":
        pytest.skip("qualified mount/Landlock/seccomp profile unavailable")
    assert result.status == "completed" and result.physical_enforcement
    assert runner.verify_outcome(result, plan)
    assert not runner.verify_outcome(copy(result), plan)
    evidence = runner.evidence_record(result)
    assert evidence["test_correctness_verified"] is False
    assert all(evidence["isolation"]["isolation"]["checks"].values())
    return json.loads(result.value)


def test_snapshot_bounds_and_links_are_checked_before_capture(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a").write_bytes(b"1234")
    with pytest.raises(ValueError, match="byte"):
        _capture(root, 8, 3)
    (root / "b").write_bytes(b"a")
    with pytest.raises(ValueError, match="count"):
        _capture(root, 1, 30)
    before, _ = _capture(root, 8, 30)
    (root / "a").write_bytes(b"4321")
    after, _ = _capture(root, 8, 30)
    assert _tree_digest(before) != _tree_digest(after)
    if sys.platform == "linux":
        (root / "linked").symlink_to(root / "a")
        with pytest.raises(ValueError, match="regular"):
            _capture(root, 8, 30)


@pytest.mark.parametrize(
    "selector", ["../escape.py", "/escape.py", "--help.py", "a.py::x;sh", "a.py -pplugin"]
)
def test_selector_catalog_cannot_supply_paths_or_cli_options(tmp_path, selector):
    operator, runner, route, action = setup(tmp_path, portable=True)
    with pytest.raises(ValueError, match="selector"):
        replace(route, selectors=(selector,))
    runner.close(operator=operator)


def test_unsupported_platform_has_no_process_or_snapshot_effects(tmp_path, monkeypatch):
    if sys.platform == "linux" and os.geteuid() == 0:
        pytest.skip("privileged Linux is an executable profile")
    operator, runner, route, action = setup(tmp_path, portable=True)
    import subprocess

    def never(*args, **kwargs):
        pytest.fail("unsupported fixed test route launched a child")

    monkeypatch.setattr(subprocess, "Popen", never)
    with pytest.raises(ValueError, match="unavailable"):
        runner.prepare_action(action, operator=operator)
    assert not list(runner.root.glob("snapshot-*"))
    assert not runner.compile_action(action, contract(action, route)).enforceable
    runner.close(operator=operator)


def test_snapshot_original_custody_aliases_and_negative_arguments(tmp_path, monkeypatch):
    # Portable state checks do not stand in for the native kernel tests below.
    operator, runner, route, action = setup(tmp_path, portable=True)
    monkeypatch.setattr(runner._engine, "_candidate", True)
    monkeypatch.setattr(runner, "_verify_runtime", lambda route: None)
    action, plan, source = prepare(runner, route, action, operator)
    assert runner.prepare_action(action, operator=operator) is action
    alias = replace(action, action_id="human-1")
    assert runner.prepare_action(alias, operator=operator) is alias
    assert len(runner._snapshots) == 1
    assert runner.validate_action_requirements(alias, contract(alias, route))
    with pytest.raises(ValueError, match="original"):
        runner.prepare_action(action, operator=object())
    for args in ({"test_id": "unit", "argv": []}, {"test_id": "other"}, {"test_id": []}):
        wrong = replace(
            action, parameters={"runtime": "ordin-owned", "tool": "run_tests", "arguments": args}
        )
        with pytest.raises(ValueError):
            runner.prepare_action(wrong, operator=operator)
    for snapshot in (
        {"reference": [], "digest": "a" * 64},
        {"reference": "fake", "digest": "a" * 64},
    ):
        wrong = replace(action, parameters={**action.parameters, "host_test_snapshot": snapshot})
        assert not runner.validate_action_requirements(wrong, contract(wrong, route))
    assert not runner.validate(copy(plan)).ok
    for change in (
        {"process": ProcessCapability(True, (), False)},
        {"process": ProcessCapability(True, (str(route.runtime.interpreter),), True)},
        {"filesystem": ()},
    ):
        assert not runner.validate_action_requirements(
            action, replace(contract(action, route), **change, contract_id="")
        )
    warn = runner.compile_action(action, contract(action, route, decision="warn")).plan
    with pytest.raises(ValueError, match="eligible"):
        runner.execute(warn, action, source, operator=operator)
    (route.project_root / "test_sample.py").write_text("def test_changed(): pass\n")
    with pytest.raises(ValueError, match="changed"):
        runner.prepare_action(action, operator=operator)
    assert len(runner._snapshots) == 1
    runner.close(operator=operator)


def test_fixed_pytest_runs_only_after_kernel_readiness_and_ignores_repo_config(
    tmp_path, monkeypatch
):
    kernel_only()
    operator, runner, route, action = setup(tmp_path)
    (route.project_root / "pytest.ini").write_text("[pytest]\naddopts = --unknown-host-option\n")
    (route.project_root / "conftest.py").write_text(
        "raise RuntimeError('conftest must not load')\n"
    )
    monkeypatch.setenv("PYTEST_ADDOPTS", "--unknown-host-option")
    monkeypatch.setenv("PYTEST_PLUGINS", "host_secret_plugin")
    monkeypatch.setenv("ORDIN_HOST_SECRET_CANARY", "not-for-tests")
    try:
        action, plan, source = prepare(runner, route, action, operator)
        result = runner.execute(plan, action, source, operator=operator)
        value = assert_kernel_result(runner, plan, result)
        assert value["exit_code"] == 0 and "1 passed" in value["output"]
        assert value["output_trust"] == "untrusted_test_diagnostic"
        assert value["test_correctness_verified"] is False
        runner.close(operator=operator)
        assert runner.verify_outcome(result, plan)
    finally:
        runner.close(operator=operator)


def test_pinned_framework_outranks_real_project_pytest_py_and_private_package_shadows(tmp_path):
    kernel_only()
    operator, runner, route, action = setup(tmp_path)
    selected = str(route.runtime.root / "site")
    (route.project_root / "test_sample.py").write_text(
        "def test_selected_framework_and_project_import():\n"
        "    import pytest, py, _pytest, project_helper\n"
        "    from pathlib import Path\n"
        f"    pinned = Path({selected!r})\n"
        "    assert Path(pytest.__file__).is_relative_to(pinned / 'pytest')\n"
        "    assert Path(_pytest.__file__).is_relative_to(pinned / '_pytest')\n"
        "    assert Path(py.__file__) == pinned / 'py.py'\n"
        f"    assert pytest.__version__ == {route.runtime.pytest_version!r}\n"
        "    assert project_helper.VALUE == 'project still importable'\n"
        "    assert not Path('/scratch/framework-shadow-marker').exists()\n"
        "    print('pinned-framework-selected')\n"
    )
    shadow = (
        "from pathlib import Path\n"
        "Path('/scratch/framework-shadow-marker').write_text('shadow executed')\n"
        "raise RuntimeError('untrusted project replaced pinned framework')\n"
    )
    for name in ("pytest.py", "py.py"):
        (route.project_root / name).write_text(shadow)
    (route.project_root / "_pytest").mkdir()
    (route.project_root / "_pytest/__init__.py").write_text(shadow)
    (route.project_root / "project_helper.py").write_text("VALUE = 'project still importable'\n")
    try:
        action, plan, source = prepare(runner, route, action, operator)
        value = assert_kernel_result(
            runner, plan, runner.execute(plan, action, source, operator=operator)
        )
        assert value["exit_code"] == 0 and "1 passed" in value["output"]
        assert "pinned-framework-selected" in value["output"]
    finally:
        runner.close(operator=operator)


def test_untrusted_tests_cannot_bypass_kernel_or_access_broker_and_host(tmp_path):
    kernel_only()
    text = """
def test_kernel_controls():
    import os, ctypes, errno
    assert 'ORDIN_HOST_SECRET_CANARY' not in os.environ
    for path in ('/etc/passwd', '/proc/self/environ', '/forbidden'):
        try:
            open(path, 'rb')
        except OSError:
            pass
        else:
            raise AssertionError('host readable')
    try:
        open(__file__, 'a')
    except OSError:
        pass
    else:
        raise AssertionError('snapshot writable')
    for fd in (0, 3, 4, 5, 6):
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            raise AssertionError('inherited descriptor')
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.syscall(41,2,1,0)==-1 and ctypes.get_errno()==errno.EPERM
    assert libc.syscall(57)==-1 and ctypes.get_errno()==errno.EPERM
    assert libc.syscall(59,ctypes.c_char_p(b'/escape'),None,None)==-1
    assert ctypes.get_errno()==errno.EPERM
    import subprocess, sys
    try:
        subprocess.Popen([sys.executable, '-c', 'raise AssertionError("compiler child escaped")'])
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError('fixed test could launch a build subprocess')
    with open('/scratch/permitted', 'w') as target:
        target.write('private bounded scratch')
"""
    operator, runner, route, action = setup(tmp_path, text)
    try:
        action, plan, source = prepare(runner, route, action, operator)
        value = assert_kernel_result(
            runner, plan, runner.execute(plan, action, source, operator=operator)
        )
        assert value["exit_code"] == 0 and "1 passed" in value["output"]
    finally:
        runner.close(operator=operator)


def test_installation_probe_does_not_execute_configured_project(tmp_path):
    kernel_only()
    operator, runner, route, action = setup(
        tmp_path, "raise RuntimeError('configured workload ran')\n"
    )
    root = tmp_path / "probe"
    root.mkdir(mode=0o700)
    probe = None
    try:
        probe, outcome, plan, evidence, description = runner.factory_probe(
            root, operator=operator, policy_digest="d" * 64
        )
        assert_kernel_result(probe, plan, outcome)
        probe.close(operator=operator)
        assert probe.verify_outcome(outcome, plan)
        assert description["scope"] == "fresh_fixed_test_fixture_only"
        assert description["execution_authority"] is False
        assert not runner._snapshots
    finally:
        if probe is not None:
            probe.close(operator=operator)
        runner.close(operator=operator)


def test_owned_test_timeout_is_unknown_without_retry(tmp_path):
    kernel_only()
    limits = ProtectedProcessLimits(timeout_ms=5000, cpu_seconds=2, memory_mib=512)
    operator, runner, route, action = setup(
        tmp_path, "def test_loop():\n    while True: pass\n", limits=limits
    )
    try:
        action, plan, source = prepare(runner, route, action, operator)
        result = runner.execute(plan, action, source, operator=operator)
        if (
            result.status == "unsupported"
            and os.environ.get("ORDIN_REQUIRED_PROTECTED_PROCESS") != "1"
        ):
            pytest.skip("qualified profile unavailable")
        assert result.status == "unknown" and result.physical_enforcement
        assert result.observation is None and runner.verify_outcome(result, plan)
        assert len(runner._jobs) == 1
    finally:
        runner.close(operator=operator)
