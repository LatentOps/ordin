import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ordin import ActionEnvelope, Ordin
from ordin import audit


def event_payload(*, hash_chain=False):
    return audit.build_audit_event(
        Ordin().review_action(ActionEnvelope.shell("git status")), hash_chain=hash_chain
    ).as_dict()


@pytest.mark.parametrize("hash_chain", [False, True])
def test_audit_rejects_escaped_non_scalar_unicode_without_crashing(tmp_path, hash_chain):
    payload = event_payload(hash_chain=hash_chain)
    payload["provenance"]["records"][0]["summary"] = "invalid\ud800"
    path = tmp_path / "invalid-unicode.jsonl"
    path.write_text(json.dumps(payload, ensure_ascii=True) + "\n", encoding="utf-8")

    result = audit.verify_audit_jsonl(path, require_hash_chain=hash_chain)

    assert not result.ok
    assert result.errors


def test_audit_diagnostics_remain_bounded_for_many_invalid_records(tmp_path):
    path = tmp_path / "invalid-records.jsonl"
    path.write_bytes(b"{}\n" * 1000)

    result = audit.verify_audit_jsonl(path)

    assert not result.ok
    assert len(result.errors) <= 64
    assert len(json.dumps(result.as_dict()).encode()) < 128 * 1024
    assert any("diagnostic limit" in error for error in result.errors)


def test_audit_diagnostic_cannot_echo_an_unbounded_invalid_field(tmp_path):
    payload = event_payload()
    payload["decision"] = "invalid" * 20000
    path = tmp_path / "invalid-field.jsonl"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    result = audit.verify_audit_jsonl(path)

    assert not result.ok
    assert max(map(len, result.errors)) <= 1024


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
@pytest.mark.parametrize("through_symlink", [False, True])
def test_audit_fifo_is_rejected_without_waiting_for_a_writer(tmp_path, through_symlink):
    fifo = tmp_path / "audit.fifo"
    os.mkfifo(fifo, 0o600)
    selected = fifo
    if through_symlink:
        selected = tmp_path / "linked.fifo"
        selected.symlink_to(fifo)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from ordin.audit import verify_audit_jsonl; "
        "r=verify_audit_jsonl(sys.argv[2]); "
        "assert not r.ok; assert any('regular' in e for e in r.errors)"
    )

    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            code,
            str(Path(audit.__file__).parents[1]),
            str(selected),
        ],
        check=True,
        timeout=5,
        capture_output=True,
        text=True,
    )


def test_audit_enforces_byte_budget_when_a_file_grows_after_initial_stat(tmp_path, monkeypatch):
    raw = (json.dumps(event_payload()) + "\n").encode()
    path = tmp_path / "growing.jsonl"
    path.write_bytes(raw)
    monkeypatch.setattr(audit, "MAX_AUDIT_BYTES", 3 * len(raw))

    with path.open("rb") as handle:

        class GrowingReader:
            grown = False
            bytes_read = 0

            def fileno(self):
                return handle.fileno()

            def readline(self, size):
                if not self.grown:
                    self.grown = True
                    with path.open("ab") as writer:
                        writer.write(raw * 4)
                data = handle.readline(size)
                self.bytes_read += len(data)
                return data

        reader = GrowingReader()
        result = audit._verify_audit_stream(reader, require_hash_chain=False)

    assert not result.ok
    assert any("byte limit" in error for error in result.errors)
    assert result.event_count <= 3
    assert reader.bytes_read <= 3 * len(raw) + 1


def test_audit_filesystem_errors_are_bounded(tmp_path, monkeypatch):
    def fail_stat(_):
        raise OSError("invalid path " + "x" * 20000)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", fail_stat)
        result = audit.verify_audit_jsonl(tmp_path / "audit.jsonl")

    assert not result.ok
    assert max(map(len, result.errors)) <= 1024


@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_valid_unicode_audit_and_regular_symlink_remain_readable(tmp_path, ensure_ascii):
    payload = event_payload(hash_chain=True)
    payload["provenance"]["records"][0]["summary"] = "caf\u00e9 \U0001f512"
    payload["event_hash"] = audit._event_hash(payload)
    path = tmp_path / "unicode.jsonl"
    path.write_text(json.dumps(payload, ensure_ascii=ensure_ascii) + "\n", encoding="utf-8")
    assert audit.verify_audit_jsonl(path, require_hash_chain=True).ok
    if os.name == "posix":
        link = tmp_path / "regular-link.jsonl"
        link.symlink_to(path)
        assert audit.verify_audit_jsonl(link, require_hash_chain=True).ok
