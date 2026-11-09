"""Deployment command formatting/validation, separate from native effect proof."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from contextlib import nullcontext

import pytest

from ordin_swarm.host_authority import HostDispatch
from ordin_swarm.host_cli import _inputs, _private_output, main
from ordin_swarm.host_runtime import ManagedToolHost


def test_seed_inputs_are_exact_unique_bounded_utf8_and_do_not_change_source(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("private input", encoding="utf-8")
    before = source.stat()
    captured = _inputs(["input.txt=" + str(source)], {"input.txt"}, maximum=32, text=True)
    assert captured == {"input.txt": b"private input"}
    after = source.stat()
    assert (before.st_ino, before.st_mode, before.st_uid) == (
        after.st_ino,
        after.st_mode,
        after.st_uid,
    )
    for values in (
        ["other=" + str(source)],
        ["input.txt=relative"],
        ["input.txt=" + str(source)] * 2,
    ):
        with pytest.raises(ValueError):
            _inputs(values, {"input.txt"}, maximum=32, text=True)
    source.write_bytes(b"\xff")
    with pytest.raises(UnicodeError):
        _inputs(["input.txt=" + str(source)], {"input.txt"}, maximum=32, text=True)


def test_operator_content_can_only_be_written_to_a_new_private_preview(tmp_path):
    if __import__("os").name == "posix":
        tmp_path.chmod(0o700)
    output = tmp_path / "preview.json"
    report = _private_output(output, {"proposal": {"content": "sensitive private text"}})
    assert "sensitive" not in json.dumps(report)
    assert json.loads(output.read_text())["proposal"]["content"] == "sensitive private text"
    with pytest.raises(FileExistsError):
        _private_output(output, {"content": "replacement"})
    if __import__("os").name == "posix":
        assert output.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("matches", [True, False])
def test_read_cas_metadata_names_actual_returned_bytes_and_separate_snapshot(tmp_path, matches):
    host = object.__new__(ManagedToolHost)
    host._operator = object()
    original = b"returned bytes"
    expected = hashlib.sha256(original).hexdigest()
    snapshots = []

    def snapshot(path, *, operator):
        assert operator is host._operator
        snapshots.append(path)
        return {
            "version": 7,
            "content_digest": expected if matches else "0" * 64,
            "bytes": len(original),
        }

    host.profile = SimpleNamespace(workspace=tmp_path)
    host._authority = SimpleNamespace(backend=SimpleNamespace(snapshot=snapshot))
    host._lineage = SimpleNamespace(
        labels_for_file=lambda name: ("private_code",),
        capture=lambda *args, **kwargs: SimpleNamespace(
            reference="resource-original", labels=("private_code",)
        ),
    )
    result = host._completed(
        "reader",
        "read_file",
        {"name": "input.txt"},
        HostDispatch("completed", (), True, True, result=SimpleNamespace(value=original)),
    )
    assert result["data"]["content_digest"] == expected
    assert result["data"]["current_version"] == 7
    assert result["data"]["version"] == (7 if matches else None)
    assert result["data"]["version_match"] is matches
    assert snapshots == [str(tmp_path / "input.txt")]


def test_cli_help_is_available_without_starting_or_importing_native_backend(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    assert "client-config" in capsys.readouterr().out


@pytest.mark.parametrize(
    "action,status,fulfillment,expected",
    [
        ("approve", "denied", None, 2),
        ("approve", "completed", None, 0),
        ("deny", "completed", None, 0),
        ("fulfill", "completed", "unknown", 2),
        ("fulfill", "completed", "denied", 2),
        ("fulfill", "completed", "completed", 0),
    ],
)
def test_operator_cli_exit_status_tracks_actual_resolution_and_fulfillment(
    tmp_path, monkeypatch, capsys, action, status, fulfillment, expected
):
    from ordin_swarm import host_cli, host_service
    from ordin_swarm.host_runtime import _result

    monkeypatch.setattr(
        host_cli, "load_host_profile", lambda path: SimpleNamespace(configuration_root=tmp_path)
    )
    monkeypatch.setattr(host_service, "connect", lambda path: nullcontext(object()))
    monkeypatch.setattr(host_cli, "_initialize_connection", lambda connection: None)
    data = (
        {
            "fulfillment": _result(
                fulfillment, data={"output": "private diagnostic", "content": "private body"}
            )
        }
        if fulfillment
        else {}
    )
    monkeypatch.setattr(host_cli, "_rpc", lambda *args: _result(status, data=data))
    arguments = [
        "operator",
        "--directory",
        str(tmp_path),
        action,
        "--request-ref",
        "original",
        "--expected-binding",
        "a" * 64,
    ]
    if action != "fulfill":
        arguments += ["--idempotency-key", "explicit-review"]
    assert main(arguments) == expected
    output = capsys.readouterr().out
    assert "private diagnostic" not in output and "private body" not in output


def test_cli_private_fulfillment_keeps_failure_status_without_public_payload(
    tmp_path, monkeypatch, capsys
):
    from ordin_swarm import host_cli, host_service
    from ordin_swarm.host_runtime import _result

    if __import__("os").name == "posix":
        tmp_path.chmod(0o700)
    monkeypatch.setattr(
        host_cli, "load_host_profile", lambda path: SimpleNamespace(configuration_root=tmp_path)
    )
    monkeypatch.setattr(host_service, "connect", lambda path: nullcontext(object()))
    monkeypatch.setattr(host_cli, "_initialize_connection", lambda connection: None)
    monkeypatch.setattr(
        host_cli,
        "_rpc",
        lambda *args: _result(
            "completed",
            data={"fulfillment": _result("unknown", data={"output": "private diagnostic"})},
        ),
    )
    output = tmp_path / "result.json"
    assert (
        main(
            [
                "operator",
                "--directory",
                str(tmp_path),
                "fulfill",
                "--request-ref",
                "original",
                "--expected-binding",
                "a" * 64,
                "--private-result",
                str(output),
            ]
        )
        == 2
    )
    assert "private diagnostic" not in capsys.readouterr().out
    assert (
        json.loads(output.read_text())["data"]["fulfillment"]["data"]["output"]
        == "private diagnostic"
    )


def test_live_doctor_offline_or_unsupported_returns_failure(tmp_path, monkeypatch, capsys):
    from ordin_swarm import host_cli

    monkeypatch.setattr(
        host_cli,
        "doctor",
        lambda *args, **kwargs: {
            "status": "live_verified",
            "supported_platform": True,
            "online_verified": False,
        },
    )
    assert main(["doctor", "--directory", str(tmp_path), "--live"]) == 2
    assert json.loads(capsys.readouterr().out)["online_verified"] is False


def test_missing_fixed_runtime_distribution_is_actionable_and_sanitized(
    tmp_path, monkeypatch, capsys
):
    from importlib.metadata import PackageNotFoundError
    from ordin.swarm import confined_tests
    from ordin_swarm import host_cli

    calls = []

    def missing(runtime, *, operator):
        calls.append(runtime)
        raise PackageNotFoundError("private distribution diagnostic")

    monkeypatch.setattr(confined_tests, "build_python_runtime_catalog", missing)
    monkeypatch.setattr(host_cli, "_document", lambda path: {})

    def initialize(directory, document, **kwargs):
        assert kwargs["with_tests"] is True
        host_cli._stage_test_runtime(tmp_path / "fresh-runtime")
        pytest.fail("missing runtime initialization claimed success")

    monkeypatch.setattr(host_cli, "initialize", initialize)
    result = main(
        [
            "init",
            "--directory",
            str(tmp_path / "new"),
            "--profile",
            str(tmp_path / "profile.json"),
            "--with-tests",
        ]
    )
    output = capsys.readouterr()
    assert result == 2 and output.out == "" and calls == [tmp_path / "fresh-runtime"]
    report = json.loads(output.err)
    assert report["reason_code"] == "host.test_runtime_missing"
    assert 'pip install . "./integrations/swarm[test-runtime]"' in report["action"]
    assert report["partial_installation"] == "retained_for_inspection"
    assert "private distribution" not in output.err and "Traceback" not in output.err


def test_runtime_staging_integrity_error_is_not_reclassified_as_missing_dependency(
    tmp_path, monkeypatch
):
    from ordin.swarm import confined_tests
    from ordin_swarm import host_cli

    original = ValueError("runtime digest changed")

    def corrupt(*args, **kwargs):
        raise original

    monkeypatch.setattr(confined_tests, "build_python_runtime_catalog", corrupt)
    with pytest.raises(ValueError) as error:
        host_cli._stage_test_runtime(tmp_path / "fresh-runtime")
    assert error.value is original and not isinstance(error.value, host_cli._TestRuntimeMissing)
