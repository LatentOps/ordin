"""Actual kernel-restricted owned fixtures; unsupported hosts stay explicit."""

from dataclasses import replace
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

import pytest

from ordin.assurance import (
    HostEvidenceSource,
    LinuxIsolationEvidence,
    LinuxSandboxTestRun,
    install_linux_vetted_runtime,
    assess_linux_vetted_isolation,
    authorize_sandbox_test,
    sandbox_test_action,
    run_sandbox_test,
    load_vetted_program,
    load_synthetic_suite,
    AuthorizedRepository,
    SyntheticPathCase,
    SyntheticPathSuite,
)
from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
from .test_validation import reference
from .test_sandbox_tests import BUG, FIX


LINUX = sys.platform == "linux"


def supported_kernel():
    if not LINUX or os.uname().machine != "x86_64":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc.syscall(444, None, 0, 1) >= 1


def receipt():
    # Data-schema example only. Actual kernel tests below obtain a sealed run.
    from ordin.assurance._sandbox_worker import LINUX_FILTER_DIGEST

    return {
        "backend": "linux-memory-only-v1",
        "landlock_abi": 1,
        "seccomp_mode": 2,
        "no_new_privileges": 1,
        "filter_digest": LINUX_FILTER_DIGEST,
        "limits": {
            "cpu_seconds": [2, 2],
            "memory_bytes": [134217728, 134217728],
            "max_processes": [1, 1],
            "max_descriptors": [3, 3],
            "core_bytes": [0, 0],
        },
        "checks": {
            name: True
            for name in (
                "filesystem_read_denied",
                "filesystem_write_denied",
                "network_socket_denied",
                "process_fork_denied",
                "executable_launch_denied",
                "memory_ceiling_enforced",
            )
        },
        "environment_empty": True,
        "pipe_only_transport": True,
        "filesystem_access": "denied",
        "network_access": "denied",
        "process_creation": "denied",
        "executable_launch": "denied",
    }


@pytest.fixture
def setup(tmp_path):
    if not supported_kernel():
        if os.environ.get("ORDIN_REQUIRE_LINUX_BROKER") == "1":
            pytest.fail("required Linux x86-64/Landlock kernel is unavailable")
        pytest.skip("Linux x86-64/Landlock kernel unavailable; no weaker broker fallback")
    target = tmp_path / "target"
    target.mkdir()
    (target / "guard.py").write_text(BUG + "# Owned initial fixture comment\n")
    data = SyntheticPathSuite(
        "linux-cases",
        (
            SyntheticPathCase("benign-child", "/synthetic/project/file", "/synthetic/project"),
            SyntheticPathCase("benign-exact", "/synthetic/project", "/synthetic/project"),
            SyntheticPathCase("adverse", "/synthetic/project-other/file", "/synthetic/project"),
        ),
    )
    (target / "suite.json").write_text(json.dumps(data.as_dict()))
    scope = AuthorizedRepository(target, REPO, "/fixture")
    program = load_vetted_program(scope, reference(scope, "guard.py"))
    suite = load_synthetic_suite(scope, reference(scope, "suite.json"))
    profile = approve(selected(tmp_path, config_profile()))
    source = HostEvidenceSource(
        "fixture-agent", REPO, "b" * 64, 1, POLICY_HASH, profile.selection_digest
    )
    with tempfile.TemporaryDirectory(prefix="ordin-linux-installed-") as directory:
        runtime = install_linux_vetted_runtime(
            Path(directory),
            forbidden_roots=(tmp_path.resolve(), Path(__file__).resolve().parents[2]),
            timeout_ms=1000,
        )

        def approve_probe(runtime=runtime):
            action = sandbox_test_action(runtime, program, suite, source)
            approval = source.record_approval(
                action, profile, receipt_id="owned-kernel-fixture-review"
            )
            isolation = assess_linux_vetted_isolation(
                scope, source, profile, approval, runtime, program, suite
            )
            return approval, isolation

        def consent(runtime=runtime):
            approval, isolation = approve_probe(runtime)
            assert isolation.status == "satisfied", isolation.proof_gaps
            return authorize_sandbox_test(
                source, profile, approval, isolation, runtime, program, suite
            )

        yield scope, source, profile, runtime, program, suite, approve_probe, consent


def test_unavailable_platform_installation_is_explicit(tmp_path):
    if LINUX:
        pytest.skip("unsupported-platform control")
    with pytest.raises(ValueError, match="unavailable"):
        install_linux_vetted_runtime(
            tmp_path.resolve(), forbidden_roots=(Path(__file__).resolve().parents[2],)
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("seccomp_mode", 0),
        ("no_new_privileges", 0),
        ("filesystem_access", "allowed"),
        ("environment_empty", False),
        ("filter_digest", "0" * 64),
        ("landlock_abi", 0),
    ],
)
def test_weak_or_changed_kernel_evidence_is_not_accepted(field, value):
    packet = receipt()
    packet[field] = value
    with pytest.raises(ValueError):
        LinuxIsolationEvidence.from_dict(packet)


def test_boolean_resource_limits_cannot_masquerade_as_integer_readback():
    packet = receipt()
    packet["limits"]["max_processes"] = [True, True]
    with pytest.raises(ValueError):
        LinuxIsolationEvidence.from_dict(packet)


def test_actual_kernel_profile_reproduces_bug_without_host_access(setup, monkeypatch):
    scope, source, profile, runtime, program, suite, _, consent = setup
    monkeypatch.setenv("AMBIENT_PRIVATE_TOKEN", "synthetic-secret-never-child")
    lease = consent()
    result = run_sandbox_test(scope, source, runtime, program, suite, lease)
    assert isinstance(result, LinuxSandboxTestRun) and result.status == "completed"
    evidence = result.isolation_evidence
    assert evidence is not None and evidence.matches(runtime)
    assert (
        all(evidence.checks.values())
        and evidence.environment_empty
        and evidence.pipe_only_transport
    )
    assert sum(not row["expected"] and row["actual"] for row in result.results) == 1
    assert "synthetic-secret-never-child" not in json.dumps(result.as_dict())
    with pytest.raises(ValueError):
        LinuxSandboxTestRun.from_dict(result.as_dict())
    assert run_sandbox_test(scope, source, runtime, program, suite, lease).status == "refused"


def test_no_approval_or_precanceled_probe_never_launches(setup, monkeypatch):
    scope, source, profile, runtime, program, suite, approve_probe, _ = setup
    action = sandbox_test_action(runtime, program, suite, source)
    approval = source.record_approval(action, profile, receipt_id="owned-canceled-probe")

    def forbidden(*args, **kwargs):
        pytest.fail("unauthorized/canceled probe launched")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    with pytest.raises(ValueError, match="approval"):
        assess_linux_vetted_isolation(
            scope, source, profile, approval.as_dict(), runtime, program, suite
        )
    cancel = threading.Event()
    cancel.set()
    result = assess_linux_vetted_isolation(
        scope, source, profile, approval, runtime, program, suite, cancel=cancel
    )
    assert result.status == "inconclusive" and result.proof_gaps


def test_worker_drift_and_command_widening_refuse_before_launch(setup, monkeypatch):
    scope, source, profile, runtime, program, suite, _, consent = setup
    lease = consent()
    runtime.worker.write_text("print('forged broker')")

    def forbidden(*args, **kwargs):
        pytest.fail("unselected worker launched")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    assert run_sandbox_test(scope, source, runtime, program, suite, lease).status == "refused"
    widened = replace(runtime, arguments=("-I", "-u", str(runtime.worker)))
    action = sandbox_test_action(widened, program, suite, source)
    approval = source.record_approval(action, profile, receipt_id="owned-widened-probe")
    assert (
        assess_linux_vetted_isolation(
            scope, source, profile, approval, widened, program, suite
        ).status
        == "inconclusive"
    )


def test_installation_rejects_invalid_budget_before_writing(setup):
    _, _, _, runtime, *_ = setup
    with tempfile.TemporaryDirectory(prefix="ordin-linux-invalid-") as directory:
        root = Path(directory)
        with pytest.raises(ValueError):
            install_linux_vetted_runtime(
                root, forbidden_roots=runtime.forbidden_roots, memory_mib=1
            )
        assert list(root.iterdir()) == []


def test_packet_cannot_forge_weaker_kernel_budget(setup, monkeypatch):
    import ordin.assurance.sandbox_tests as module

    scope, source, profile, runtime, program, suite, _, consent = setup
    lease = consent()
    original = module.run_test_process

    def forge(*args, **kwargs):
        observed = original(*args, **kwargs)
        packet = json.loads(observed["stdout"])
        packet["isolation"]["limits"]["memory_bytes"] = [67108864, 67108864]
        observed["stdout"] = json.dumps(packet).encode()
        return observed

    monkeypatch.setattr(module, "run_test_process", forge)
    result = run_sandbox_test(scope, source, runtime, program, suite, lease)
    assert result.status == "malformed" and not result.results and result.isolation_evidence is None


def test_isolation_helper_cannot_restrict_an_importing_parent():
    from ordin.assurance._sandbox_worker import execute_request

    with pytest.raises(ValueError, match="disposable worker"):
        execute_request({}, isolated=True)


@pytest.mark.parametrize(
    "code,expected",
    [
        (FIX, "fixed-verified"),
        (BUG, "still-vulnerable"),
        ("def within_root(path, root):\n    return path == root\n", "inconclusive"),
    ],
)
def test_source_fix_and_preserved_benign_control_run_under_kernel_profile(
    setup, tmp_path, code, expected
):
    from .test_sandbox_validation import selections
    from ordin.assurance import verify_source_fix

    scope, source, profile, runtime, program, suite, _, consent = setup
    adapted = (scope, source, runtime, program, suite, consent, runtime.worker)
    patch, original, before, after, a, b = selections(adapted, tmp_path, code)
    # Replace helper's synthetic isolation assertions with observed kernel
    # assessment receipts for both selected original/candidate programs.
    for chosen, selected_profile in ((before, a), (after, b)):
        action = sandbox_test_action(
            chosen["runtime"], chosen["program"], chosen["suite"], chosen["source"]
        )
        approval = chosen["source"].record_approval(
            action, selected_profile, receipt_id="owned-source-fix-review"
        )
        isolation = assess_linux_vetted_isolation(
            chosen["scope"],
            chosen["source"],
            selected_profile,
            approval,
            chosen["runtime"],
            chosen["program"],
            chosen["suite"],
        )
        assert isolation.status == "satisfied", isolation.proof_gaps
        chosen["consent"] = authorize_sandbox_test(
            chosen["source"],
            selected_profile,
            approval,
            isolation,
            chosen["runtime"],
            chosen["program"],
            chosen["suite"],
        )
    result = verify_source_fix(
        patch, original, before=before, after=after, before_profile=a, after_profile=b
    )
    assert result.result == expected and result.original_run_digest and result.candidate_run_digest
    if expected == "fixed-verified":
        assert not result.proof_gaps and result.authority_delta == "narrowed"
    elif expected == "inconclusive":
        assert result.benign_regressions == 1 and result.proof_gaps
    assert not patch.applied and not result.integrated


def test_kernel_cpu_hard_limit_terminates_owned_busy_fixture(setup):
    import subprocess

    _, _, _, runtime, *_ = setup
    code = (
        "import runpy,sys; sys.argv=[sys.argv[1],'--linux-isolated']; "
        "worker=runpy.run_path(sys.argv[0]); "
        "worker['_isolate_linux']({'cpu_seconds':1,'memory_mib':128}); "
        "exec('while True:\\n    pass')"
    )
    # Fixed project-owned CPU control only, never target source or caller code.
    result = subprocess.run(
        [str(runtime.executable), "-I", "-S", "-c", code, str(runtime.worker)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        cwd=runtime.trusted_cwd,
        timeout=5,
    )
    assert result.returncode == -9 and not result.stdout


def test_inherited_owned_file_descriptor_is_closed_before_vetted_execution(setup):
    import subprocess

    _, _, _, runtime, *_ = setup
    canary = runtime.trusted_cwd / "owned-fd-canary.txt"
    canary.write_bytes(b"Synthetic inherited file marker; never exported")
    descriptor = os.open(canary, os.O_RDONLY)
    code = (
        "import errno,os,runpy,sys; fd=int(sys.argv[2]); sys.argv=[sys.argv[1],'--linux-isolated']; "
        "worker=runpy.run_path(sys.argv[0]); worker['_isolate_linux']({'cpu_seconds':2,'memory_mib':128}); "
        "exec('try:\\n    os.read(fd,1)\\nexcept OSError as error:\\n    assert error.errno==errno.EBADF\\nelse:\\n    raise AssertionError(\\\"inherited file remained readable\\\")')"
    )
    try:
        result = subprocess.run(
            [str(runtime.executable), "-I", "-S", "-c", code, str(runtime.worker), str(descriptor)],
            pass_fds=(descriptor,),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            cwd=runtime.trusted_cwd,
            timeout=5,
        )
    finally:
        os.close(descriptor)
    assert result.returncode == 0 and not result.stdout, result.stderr


def test_kernel_profile_refuses_resource_limit_widening(setup):
    import subprocess

    _, _, _, runtime, *_ = setup
    code = (
        "import ctypes,errno,runpy,sys; sys.argv=[sys.argv[1],'--linux-isolated']; "
        "worker=runpy.run_path(sys.argv[0]); worker['_isolate_linux']({'cpu_seconds':2,'memory_mib':128}); "
        "libc=ctypes.CDLL(None,use_errno=True); libc.syscall.restype=ctypes.c_long; "
        "limits=(ctypes.c_uint64*2)(268435456,268435456); "
        "result=libc.syscall(302,0,9,ctypes.byref(limits),None); "
        "assert result==-1 and ctypes.get_errno()==errno.EPERM"
    )
    result = subprocess.run(
        [str(runtime.executable), "-I", "-S", "-c", code, str(runtime.worker)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        cwd=runtime.trusted_cwd,
        timeout=5,
    )
    assert result.returncode == 0 and not result.stdout, result.stderr
