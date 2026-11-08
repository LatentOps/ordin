"""Deployment command formatting/validation, separate from native effect proof."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

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
