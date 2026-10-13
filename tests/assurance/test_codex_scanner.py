"""Trusted fake processes exercise wrapper states; no scanner/model/account."""

from dataclasses import replace
import hashlib
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import threading

import pytest

from ordin.assurance.codex_security.scanner import (
    ScannerSelection,
    configuration_review_digest,
    inspect_scanner,
    mock_scanner_run,
    run_diff_scan,
    scan_action,
    _run,
)
from ordin.assurance.host import HostEvidenceSource
from ordin.assurance.inventory import AuthorizedRepository
from ordin.assurance.profiles import load_approved_profile

from .test_codex_import import documents
from .test_profiles import config_profile, selected, POLICY_HASH


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def installation(tmp_path):
    # The selected runtime/installation is outside every actual checkout.
    with tempfile.TemporaryDirectory(prefix="ordin-scanner-fixture-") as name:
        root = Path(name).resolve(strict=True)
        for part in ("install", "cwd", "private", "target"):
            (root / part).mkdir(mode=0o700)
        entrypoint = root / "install/fake.py"
        entrypoint.write_text("print('0.2.0')\n", encoding="utf-8")
        # Hosted/venv Python launchers may be symlinks. Select and fingerprint
        # their actual native binary; production refuses linked selections.
        interpreter = Path(sys.executable).resolve(strict=True)
        selection = ScannerSelection(
            interpreter,
            sha(interpreter),
            "0.2.0",
            root / "cwd",
            root / "private",
            entrypoint=entrypoint,
            entrypoint_sha256=sha(entrypoint),
            expected_plugin_version="0.1.0",
            timeout_seconds=2,
        )
        repo_scope = replace(config_profile().repository, revision="b" * 40)
        repository = AuthorizedRepository(root / "target", repo_scope, "/fixture")
        profile = config_profile()
        profile = replace(profile, repository=repo_scope)
        protected = selected(tmp_path, profile, repository=repo_scope)
        approved = load_approved_profile(
            protected, current_repository=repo_scope, active_runtime_policy_digest=POLICY_HASH
        )
        source = HostEvidenceSource(
            "operator", repo_scope, "c" * 64, 1, POLICY_HASH, approved.selection_digest
        )
        yield selection, repository, approved, source


def fake(
    selection,
    *,
    code=0,
    version="0.2.0",
    completeness="complete",
    malformed=False,
    info=None,
    body="",
    scan_body="",
    final_body="",
):
    assert selection.entrypoint is not None
    findings, coverage, manifest = documents([], completeness=completeness, revision="b" * 40)
    default_info = {
        "sdkVersion": "0.2.0",
        "cliVersion": "0.2.0",
        "bundledPluginVersion": "0.1.0",
        "scanMcp": False,
        "configuration": {},
    }
    script = f"""import sys, json, hashlib, os, time
from pathlib import Path
args = sys.argv[1:]
{body}
if args == ["--version"]:
    print({version!r})
elif args == ["scan", "--help"]:
    print("--diff --head --output-dir --auth --provider --mode --json")
elif args == ["info", "--json"]:
    print({"invalid-json"!r} if {malformed!r} else json.dumps({(default_info if info is None else info)!r}))
else:
    {scan_body or "pass"}
    output = Path(args[args.index("--output-dir") + 1])
    output.mkdir()
    manifest = {manifest!r}
    for name, packet in [("findings.json", {findings!r}), ("coverage.json", {coverage!r})]:
        raw = json.dumps(packet).encode()
        (output / name).write_bytes(raw)
        manifest["scan"]["artifacts"].append({{"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "mediaType": "application/json"}})
    (output / "scan-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    {final_body or "pass"}
    print("private-source-body and token must never appear in report")
    print(os.environ.get("OPENAI_API_KEY", ""), file=sys.stderr)
    sys.exit({code})
"""
    selection.entrypoint.write_text(script, encoding="utf-8")
    return replace(selection, entrypoint_sha256=sha(selection.entrypoint))


def consent(selection, repository, profile, source, **extra):
    review = configuration_review_digest(
        selection,
        repository,
        worktree_root=repository.root,
        reviewed_files=extra.get("reviewed_files", ()),
    )
    action = scan_action(
        selection, repository, base_revision="a" * 40, reviewed_config_digest=review
    )
    return dict(
        worktree_root=repository.root,
        source=source,
        profile=profile,
        approval=source.record_approval(action, profile, receipt_id="upload-reviewed"),
        base_revision="a" * 40,
        reviewed_config_digest=review,
        isolation=source.record_assessment(
            action,
            profile,
            assessment_id="sandbox-verified",
            invariant_id="scanner.isolation",
            kind="scanner_isolation",
            status="satisfied",
        ),
        credentials={"OPENAI_API_KEY": "synthetic-test-token"},
        **extra,
    )


@pytest.mark.parametrize(
    "code,status",
    [
        (0, "completed"),
        (1, "severity_violation"),
        (2, "incomplete"),
        (130, "canceled"),
        (143, "canceled"),
    ],
)
def test_scan_preserves_states_and_redacts_raw_outputs(installation, code, status, monkeypatch):
    selection, repository, profile, source = installation
    selection = fake(
        selection, code=code, scan_body="assert 'AMBIENT_PRIVATE_TOKEN' not in os.environ"
    )
    monkeypatch.setenv("AMBIENT_PRIVATE_TOKEN", "never-inherit")
    result = run_diff_scan(selection, repository, **consent(selection, repository, profile, source))
    assert result.status == status and result.exit_code == code
    text = json.dumps(result.as_dict())
    assert "synthetic-test-token" not in text and "private-source-body" not in text
    assert result.model_or_network_enabled and result.observed_cli_version == "0.2.0"
    if code in {0, 1}:
        assert result.completeness == "complete" and result.imported_report_digest


def test_partial_zero_findings_is_incomplete(installation):
    selection, repository, profile, source = installation
    selection = fake(selection, completeness="partial")
    result = run_diff_scan(selection, repository, **consent(selection, repository, profile, source))
    assert result.status == "incomplete" and result.completeness == "partial"


def test_invalid_export_schema_never_becomes_success(installation):
    selection, repository, profile, source = installation
    selection = fake(
        selection, final_body="(output / 'findings.json').write_text('{}', encoding='utf-8')"
    )
    result = run_diff_scan(selection, repository, **consent(selection, repository, profile, source))
    assert (
        result.status == "incomplete" and result.exit_code == 0 and result.completeness == "unknown"
    )


def test_inflight_cancel_ends_process_tree(installation):
    selection = fake(installation[0], body="time.sleep(60)")
    cancel = threading.Event()
    timer = threading.Timer(0.3, cancel.set)
    timer.start()
    try:
        result = inspect_scanner(selection, cancel=cancel)
    finally:
        timer.cancel()
    assert result.status == "canceled" and result.elapsed_ms < 4000


def test_inspection_timeout_not_replaced_by_json_error(installation):
    selection = fake(installation[0], body="if args == ['info', '--json']: time.sleep(60)")
    result = inspect_scanner(replace(selection, timeout_seconds=0.5))
    assert result.status == "timeout"


@pytest.mark.parametrize(
    "version,malformed,status",
    [
        ("0.3.0", False, "version_mismatch"),
        ("0.2.0", True, "error"),
        ("bad\nversion", False, "error"),
    ],
)
def test_installed_version_and_metadata_refuse_drift(installation, version, malformed, status):
    selection = fake(installation[0], version=version, malformed=malformed)
    result = inspect_scanner(selection)
    assert result.status == status and not result.model_or_network_enabled


@pytest.mark.parametrize("failure", ["job_inventory", "process_wait"])
def test_unconfirmed_process_cleanup_never_yields_scanner_evidence(
    installation, monkeypatch, failure
):
    from ordin.assurance.codex_security import scanner

    launch = scanner.launch_managed_process
    cleanup_attempts = []

    def failing_cleanup(*args, **kwargs):
        process, tree = launch(*args, **kwargs)
        close, wait = tree.close, process.wait

        def close_owned_tree():
            try:
                close()
            finally:
                cleanup_attempts.append("close")
            if failure == "job_inventory":
                raise OSError("owned synthetic cleanup inventory failure")

        def wait_owned_process(*args, **kwargs):
            result = wait(*args, **kwargs)
            cleanup_attempts.append("wait")
            if failure == "process_wait":
                raise subprocess.TimeoutExpired("owned synthetic scanner", 2)
            return result

        monkeypatch.setattr(tree, "close", close_owned_tree)
        monkeypatch.setattr(process, "wait", wait_owned_process)
        return process, tree

    monkeypatch.setattr(scanner, "launch_managed_process", failing_cleanup)
    result = inspect_scanner(fake(installation[0]))
    assert result.status == "error" and result.completeness == "unknown"
    assert result.observed_cli_version is None and result.imported_report_digest is None
    assert not result.model_or_network_enabled
    assert cleanup_attempts == ["close", "wait"]


@pytest.mark.parametrize(
    "body,status",
    [
        ("time.sleep(60)", "timeout"),
        ("sys.stdout.write('x' * 200000); sys.stdout.flush(); time.sleep(60)", "output_limit"),
    ],
)
def test_process_timeout_output_budget_and_no_raw_diagnostics(installation, body, status):
    selection = replace(
        fake(installation[0], body=body), timeout_seconds=0.5, max_output_bytes=1024
    )
    result = inspect_scanner(selection)
    assert result.status == status and result.stdout_bytes <= 1024 and result.elapsed_ms < 4000


def test_timeout_kills_inherited_pipe_child(installation):
    selection = fake(
        installation[0],
        body="import subprocess; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); time.sleep(60)",
    )
    selection = replace(selection, timeout_seconds=0.5)
    result = inspect_scanner(selection)
    assert result.status == "timeout" and result.elapsed_ms < 4000


def test_explicit_cancel_does_not_launch_and_returns_cancel(installation):
    cancel = threading.Event()
    cancel.set()
    result = inspect_scanner(fake(installation[0]), cancel=cancel)
    assert result.status == "canceled" and result.exit_code is None


def test_missing_changed_and_unexecutable_selection(installation):
    selection = fake(installation[0])
    assert selection.entrypoint is not None
    selection.entrypoint.write_text("raise RuntimeError('must not run')", encoding="utf-8")
    assert inspect_scanner(selection).status == "error"
    assert inspect_scanner(
        replace(selection, executable=selection.trusted_cwd / "missing.exe")
    ).status in {"error", "unavailable"}
    selection.entrypoint.write_text("not an executable", encoding="utf-8")
    selected_file = replace(
        selection,
        executable=selection.entrypoint,
        executable_sha256=sha(selection.entrypoint),
        entrypoint=None,
        entrypoint_sha256=None,
    )
    assert inspect_scanner(selected_file).status == "error"


def test_approval_config_and_isolation_cannot_be_invented(installation):
    selection, repository, profile, source = installation
    selection = fake(selection)
    arguments = consent(selection, repository, profile, source)
    for changes in (
        {"credentials": {}},
        {"approval": arguments["approval"].as_dict()},
        {"isolation": arguments["isolation"].as_dict()},
        {"base_revision": "origin/main"},
        {"reviewed_config_digest": "f" * 64},
    ):
        with pytest.raises(ValueError):
            run_diff_scan(selection, repository, **(arguments | changes))
    (repository.root / ".codex").mkdir()
    config = repository.root / ".codex/config.toml"
    config.write_text("[mcp_servers.hostile]\ncommand='evil'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not separately reviewed"):
        run_diff_scan(selection, repository, **arguments)
    pins = ((config, sha(config)),)
    arguments = consent(selection, repository, profile, source, reviewed_files=pins)
    config.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError):
        run_diff_scan(selection, repository, **arguments)


def test_nested_worktree_and_state_reuse_refused(installation):
    selection, repository, _, _ = installation
    (repository.root.parent / ".git").mkdir()
    with pytest.raises(ValueError, match="outside"):
        configuration_review_digest(selection, repository, worktree_root=repository.root)
    (selection.private_state_root / "config.toml").write_text("hostile", encoding="utf-8")
    with pytest.raises(ValueError, match="fresh"):
        inspect_scanner(selection)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, -1])
def test_nonfinite_or_invalid_timeout_refused(installation, value):
    with pytest.raises(ValueError):
        replace(installation[0], timeout_seconds=value)


def test_mock_mode_never_spawns(monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("mock spawned"))
    assert mock_scanner_run(exit_code=1).status == "severity_violation"
    assert mock_scanner_run(completeness="partial").status == "incomplete"
    assert mock_scanner_run(exit_code=130).status == "canceled"
