import io
from pathlib import Path
import runpy
from urllib.error import HTTPError

import pytest


def checker():
    return runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/check_hermes_integration.py")
    )


def test_transient_source_download_retries_without_changing_bytes(monkeypatch):
    module = checker()
    calls, sleeps = [], []

    def download(request, timeout):
        calls.append(request.full_url)
        assert timeout == 30
        if len(calls) == 1:
            raise HTTPError(request.full_url, 429, "rate limited", {}, None)
        return io.BytesIO(b"exact pinned source")

    module["_download_source"].__globals__["urlopen"] = download
    monkeypatch.setattr(module["time"], "sleep", sleeps.append)
    assert module["_download_source"]("https://example.invalid/pinned") == b"exact pinned source"
    assert len(calls) == 2 and sleeps == [1]


@pytest.mark.parametrize("code,attempts", [(404, 1), (429, 3), (503, 3)])
def test_source_download_failure_is_bounded_and_propagated(monkeypatch, code, attempts):
    module = checker()
    calls, sleeps = [], []

    def download(request, timeout):
        calls.append(request.full_url)
        raise HTTPError(request.full_url, code, "fixture failure", {}, None)

    module["_download_source"].__globals__["urlopen"] = download
    monkeypatch.setattr(module["time"], "sleep", sleeps.append)
    with pytest.raises(HTTPError):
        module["_download_source"]("https://example.invalid/pinned")
    assert len(calls) == attempts
    assert len(sleeps) == attempts - 1


def test_source_hash_mismatch_still_stops_before_loading_upstream_code(tmp_path):
    module = checker()
    path = tmp_path / "agent/shell_hooks.py"
    path.parent.mkdir()
    path.write_bytes(b"raise RuntimeError('untrusted bytes must not execute')")
    with pytest.raises(AssertionError, match="pinned_source:agent/shell_hooks.py"):
        module["run"](tmp_path)
