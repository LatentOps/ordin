"""Unused optional test defaults cannot prevent ordinary backend construction."""

from pathlib import Path
import sys

import pytest

from ordin.swarm.confined_tests import PythonRuntimeCatalog, TestRoute
from ordin.swarm.managed_process import ProtectedProcessLimits
from ordin.swarm.owned_tools import LinuxOwnedToolsBackend


def constructor_only(monkeypatch):
    # Portable configuration validation only: no installer, process or physical claim.
    monkeypatch.setattr(LinuxOwnedToolsBackend, "_install", lambda self: None)


def test_no_test_routes_never_constructs_or_validates_runner_limits(tmp_path, monkeypatch):
    constructor_only(monkeypatch)

    def unused_limits(*args, **kwargs):
        pytest.fail("test-less backend constructed unrelated process limits")

    monkeypatch.setattr("ordin.swarm.owned_tools.ProtectedProcessLimits", unused_limits)
    backend = LinuxOwnedToolsBackend(
        tmp_path / "workspace",
        ("report.txt",),
        tmp_path / "install",
        operator=object(),
        max_payload_bytes=16384,
    )
    try:
        assert backend.test_limits is None and backend._test_runner is None
    finally:
        backend.close()


@pytest.mark.parametrize("payload", [8192, 16384, 65536])
def test_configured_default_limits_satisfy_real_strict_quota_geometry(
    tmp_path, monkeypatch, payload
):
    constructor_only(monkeypatch)
    project, runtime = tmp_path / "project", tmp_path / "runtime"
    project.mkdir()
    runtime.mkdir()
    catalog = PythonRuntimeCatalog(
        runtime, "a" * 64, Path(sys.executable).resolve(), "b" * 64, "/fixed-stdlib", "fixed"
    )
    route = TestRoute("unit", project, ("test_unit.py",), catalog)
    backend = LinuxOwnedToolsBackend(
        tmp_path / "workspace",
        ("report.txt",),
        tmp_path / "install",
        operator=object(),
        test_routes=(route,),
        max_payload_bytes=payload,
    )
    try:
        limits = backend.test_limits
        assert type(limits) is ProtectedProcessLimits
        assert (
            limits.output_bytes == payload
            and limits.scratch_bytes == 1048576
            and limits.scratch_inodes == 256
        )
        assert limits.scratch_bytes // min(limits.output_bytes, 65536) + 3 < limits.scratch_inodes
        assert ProtectedProcessLimits(**limits.as_dict()) == limits
    finally:
        backend.close()
