"""Actual bounded processes over a fake approved broker; physical isolation is not claimed."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time

import pytest

from ordin.assurance import HostEvidenceSource
from ordin.assurance.synthetic_tests import (
    SyntheticPathCase,
    SyntheticPathSuite,
    load_vetted_program,
    load_synthetic_suite,
)
from ordin.assurance.sandbox_tests import (
    VettedSandboxRuntime,
    SandboxTestRun,
    sandbox_test_action,
    authorize_sandbox_test,
    run_sandbox_test,
    run_sandbox_test_async,
)
from ordin.assurance.inventory import AuthorizedRepository
from ordin.assurance._sandbox_worker import vet_program
from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile
from .test_validation import reference

BUG = "def within_root(path, root):\n    return path.startswith(root)\n"
FIX = "def within_root(path, root):\n    return path == root or path.startswith(root + '/')\n"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def setup(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "guard.py").write_text(BUG + "# sk-synthetic-private-comment\n", encoding="utf-8")
    suite_data = SyntheticPathSuite(
        "synthetic-paths",
        (
            SyntheticPathCase(
                "prefix-collision", "/synthetic/project-other/file", "/synthetic/project"
            ),
            SyntheticPathCase("benign-child", "/synthetic/project/file", "/synthetic/project"),
            SyntheticPathCase("benign-exact", "/synthetic/project", "/synthetic/project"),
            SyntheticPathCase("outside", "/synthetic/other", "/synthetic/project"),
        ),
    )
    (target / "suite.json").write_text(json.dumps(suite_data.as_dict()), encoding="utf-8")
    scope = AuthorizedRepository(target.resolve(), REPO, "/fixture")
    program = load_vetted_program(scope, reference(scope, "guard.py"))
    suite = load_synthetic_suite(scope, reference(scope, "suite.json"))
    profile = approve(selected(tmp_path, config_profile()))
    source = HostEvidenceSource(
        "fixture-agent", REPO, "b" * 64, 1, POLICY_HASH, profile.selection_digest
    )
    monkeypatch.setenv("AMBIENT_PRIVATE_TOKEN", "synthetic-ambient-secret")
    with tempfile.TemporaryDirectory(prefix="ordin-test-broker-") as directory:
        root = Path(directory)
        for name in ("install", "cwd", "home"):
            (root / name).mkdir(mode=0o700)
        worker = root / "install/_sandbox_worker.py"
        shipped = (
            Path(__file__).resolve().parents[2] / "ordin/assurance/_sandbox_worker.py"
        ).read_text()
        shipped = shipped.replace(
            "def main():\n",
            "def main():\n    import os\n    assert 'AMBIENT_PRIVATE_TOKEN' not in os.environ\n    assert 'OPENAI_API_KEY' not in os.environ\n",
        )
        worker.write_text(shipped, encoding="utf-8")
        # Installed-wheel tests may themselves run from a workspace venv. The
        # selected broker must still live outside every excluded Git/target
        # root; its standalone worker uses only the base interpreter's stdlib.
        broker_python = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        runtime = VettedSandboxRuntime(
            broker_python,
            sha(broker_python),
            worker,
            sha(worker),
            ("-I", "-u", str(worker)),
            root / "cwd",
            root / "home",
            "d" * 64,
            (target.resolve(), Path(__file__).resolve().parents[2]),
            timeout_ms=1000,
        )

        def consent(runtime=runtime, program=program, suite=suite, lifetime=120):
            action = sandbox_test_action(runtime, program, suite, source)
            approval = source.record_approval(action, profile, receipt_id="synthetic-test-approval")
            isolation = source.record_assessment(
                action,
                profile,
                assessment_id="synthetic-isolation",
                invariant_id="validation.sandbox",
                kind="validation_isolation",
                status="satisfied",
            )
            return authorize_sandbox_test(
                source,
                profile,
                approval,
                isolation,
                runtime,
                program,
                suite,
                lifetime_seconds=lifetime,
            )

        yield scope, source, runtime, program, suite, consent, worker


def test_actual_vetted_execution_and_one_use_protected_scope(setup):
    scope, source, runtime, program, suite, consent, _ = setup
    receipt = consent()
    result = run_sandbox_test(scope, source, runtime, program, suite, receipt)
    assert result.status == "completed" and result.exit_code == 0 and len(result.results) == 4
    assert sum(not row["expected"] and row["actual"] for row in result.results) == 1
    assert "sk-synthetic" not in program._program and "private-comment" not in repr(program)
    assert "project-other" not in json.dumps(result.as_dict())
    assert run_sandbox_test(scope, source, runtime, program, suite, receipt).status == "refused"
    with pytest.raises(ValueError):
        SandboxTestRun.from_dict(result.as_dict())


@pytest.mark.parametrize(
    "code",
    [
        "import os\ndef within_root(path, root): return True",
        "def within_root(path, root): return __import__('os').system(path)",
        "def within_root(path, root):\n    while True: pass",
        "@print\ndef within_root(path, root): return path == root",
        "def within_root(path, root): return path.__class__",
        "def within_root(path, root): return path.startswith('sk-private-token')",
    ],
)
def test_unvetted_source_cannot_reach_a_broker(code):
    with pytest.raises(ValueError):
        vet_program(code)


@pytest.mark.parametrize(
    "behavior,expected",
    [
        ("timeout", "timeout"),
        ("stdout_flood", "output_limit"),
        ("stderr_flood", "output_limit"),
        ("malformed", "malformed"),
        ("wrong_binding", "malformed"),
        ("wrong_type", "malformed"),
        ("child_hang", "timeout"),
    ],
)
def test_failures_never_become_success_or_public_diagnostics(setup, behavior, expected):
    scope, source, runtime, program, suite, consent, worker = setup
    base = worker.read_text()
    if behavior == "timeout":
        code = "import time; time.sleep(60)"
    elif behavior == "child_hang":
        code = "import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); pathlib.Path('child.pid').write_text(str(p.pid)); time.sleep(60)"
    elif behavior in {"stdout_flood", "stderr_flood"}:
        channel = "stdout" if behavior == "stdout_flood" else "stderr"
        code = f"import sys,time; sys.{channel}.write('synthetic-private-output ' * 10000); sys.{channel}.flush(); time.sleep(60)"
    elif behavior == "malformed":
        code = "print('synthetic-private-output not-json')"
    elif behavior == "wrong_binding":
        code = base.replace(
            '"request_digest": packet["request_digest"]', '"request_digest": "f" * 64'
        )
    else:
        code = base.replace('"actual": actual', '"actual": 1')
    worker.write_text(code, encoding="utf-8")
    runtime = replace(
        runtime,
        worker_sha256=sha(worker),
        timeout_ms=300 if behavior == "timeout" else 2000,
    )
    result = run_sandbox_test(scope, source, runtime, program, suite, consent(runtime=runtime))
    assert result.status == expected and result.proof_gaps
    assert "synthetic-private-output" not in json.dumps(result.as_dict())
    assert not result.results
    if behavior == "child_hang":
        child = int((runtime.trusted_cwd / "child.pid").read_text())
        import os

        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
            kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
            handle = kernel.OpenProcess(0x100000, False, child)
            if handle:
                try:
                    assert kernel.WaitForSingleObject(handle, 0) == 0
                finally:
                    kernel.CloseHandle(handle)
        else:
            with pytest.raises(ProcessLookupError):
                os.kill(child, 0)


def test_hash_and_source_drift_refused_before_launch(setup, monkeypatch):
    scope, source, runtime, program, suite, consent, worker = setup
    lease = consent()
    worker.write_text("raise RuntimeError('changed')", encoding="utf-8")
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("drifted worker launched"))
    assert run_sandbox_test(scope, source, runtime, program, suite, lease).status == "refused"


def test_broker_inside_excluded_target_is_refused_before_launch(setup, monkeypatch):
    scope, source, runtime, program, suite, consent, _ = setup
    inside_target = scope.root / "fake-native-broker.exe"
    inside_target.write_bytes(b"Owned synthetic binary marker; never executable.")
    untrusted = replace(runtime, executable=inside_target, executable_sha256=sha(inside_target))
    lease = consent(runtime=untrusted)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("target broker launched"))
    assert run_sandbox_test(scope, source, untrusted, program, suite, lease).status == "refused"


def test_missing_consent_and_precancel_do_not_launch(setup, monkeypatch):
    scope, source, runtime, program, suite, consent, _ = setup
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("unapproved test launched"))
    assert run_sandbox_test(scope, source, runtime, program, suite, None).status == "refused"
    cancel = threading.Event()
    cancel.set()
    assert (
        run_sandbox_test(scope, source, runtime, program, suite, consent(), cancel=cancel).status
        == "canceled"
    )


def test_async_cancel_stops_the_approved_process(setup):
    import asyncio

    scope, source, runtime, program, suite, consent, worker = setup
    worker.write_text("import time; time.sleep(60)", encoding="utf-8")
    runtime = replace(runtime, worker_sha256=sha(worker), timeout_ms=2000)
    lease = consent(runtime=runtime)

    async def run():
        task = asyncio.create_task(
            run_sandbox_test_async(scope, source, runtime, program, suite, lease)
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    started = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - started < 5


def test_expired_scope_and_selected_source_drift_never_launch(setup, monkeypatch):
    scope, source, runtime, program, suite, consent, _ = setup
    lease = consent(lifetime=1)
    time.sleep(1.05)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("stale scope launched"))
    assert run_sandbox_test(scope, source, runtime, program, suite, lease).status == "refused"
    fresh = consent()
    (scope.root / "guard.py").write_text(FIX, encoding="utf-8")
    assert run_sandbox_test(scope, source, runtime, program, suite, fresh).status == "refused"


def test_scope_expiring_during_run_does_not_become_success(setup):
    scope, source, runtime, program, suite, consent, worker = setup
    code = worker.read_text().replace(
        "def main():\n", "def main():\n    import time\n    time.sleep(1.3)\n"
    )
    worker.write_text(code, encoding="utf-8")
    runtime = replace(runtime, worker_sha256=sha(worker), timeout_ms=3000)
    result = run_sandbox_test(
        scope, source, runtime, program, suite, consent(runtime=runtime, lifetime=1)
    )
    assert result.status == "malformed" and not result.results and result.proof_gaps
