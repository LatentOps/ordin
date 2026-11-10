"""Portable fixture trees and mocked commands; never copy or execute a real runtime."""

from copy import deepcopy
import io
import json
import os
import subprocess
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_protected_runtime_ci as driver
from scripts import check_protected_runtime as collector


@pytest.fixture(autouse=True)
def isolated_os_adapter(monkeypatch):
    # Driver OS fault injection must not replace pytest/pathlib's own stat/open.
    adapter = SimpleNamespace(**vars(os))
    if os.name == "nt":
        # Windows fd/path inode identities differ; model Linux's common identity
        # while still reading only the tiny regular fixture files through real FDs.
        paths = {}
        adapter.O_NOFOLLOW = 1 << 28
        adapter.O_DIRECTORY = 1 << 29
        adapter.O_NONBLOCK = 1 << 27

        def open_file(path, flags, *args, **kwargs):
            descriptor = os.open(
                path,
                flags & ~(adapter.O_NOFOLLOW | adapter.O_DIRECTORY | adapter.O_NONBLOCK),
                *args,
                **kwargs,
            )
            paths[descriptor] = Path(path)
            return descriptor

        adapter.open = open_file
        adapter.fstat = lambda descriptor: paths[descriptor].stat()
        # Model POSIX fd chmod only for tiny Windows fixture files.
        adapter.fchmod = lambda descriptor, mode: os.chmod(paths[descriptor], mode)
    monkeypatch.setattr(driver, "os", adapter)
    monkeypatch.setattr(driver, "subprocess", SimpleNamespace(**vars(subprocess)))


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_descriptor_controls_have_no_unsupported_platform_fallback(monkeypatch, flag):
    monkeypatch.setattr(driver.os, flag, None)
    with pytest.raises(ValueError, match="unavailable"):
        driver._posix_flag(flag)
    monkeypatch.setattr(driver.os, "fchown", None, raising=False)
    with pytest.raises(ValueError, match="unavailable"):
        driver._set_export_metadata(42, 1001, 1000, 0o644)


def private_writer_fixture(tmp_path, monkeypatch, *, failure=None):
    path = tmp_path / "created"
    events, descriptors = [], []
    state = {"mode": None}
    original_open, original_fdopen, original_chmod = (
        driver.os.open,
        driver.os.fdopen,
        driver.os.fchmod,
    )

    class SelectedPath:
        def __fspath__(self):
            return os.fspath(path)

        def chmod(self, mode):
            pytest.fail("private writer changed permissions by pathname")

    def open_file(selected, flags, mode):
        assert mode == 0o600
        assert flags & driver.os.O_CREAT and flags & driver.os.O_EXCL
        assert flags & driver._posix_flag("O_NOFOLLOW")
        descriptor = original_open(selected, flags, mode)
        descriptors.append(descriptor)
        events.append("create_private")
        state["mode"] = mode
        return descriptor

    class File:
        def __init__(self, descriptor, *, closefd):
            self.handle = original_fdopen(descriptor, "wb", closefd=closefd)

        def __enter__(self):
            self.handle.__enter__()
            return self

        def __exit__(self, *args):
            events.append("close")
            result = self.handle.__exit__(*args)
            if failure == "close":
                raise OSError("injected stream close failure")
            return result

        def fileno(self):
            return self.handle.fileno()

        def write(self, data):
            events.append("write")
            if failure in {"write", "short"}:
                written = self.handle.write(data[:1])
                if failure == "write":
                    raise OSError("injected write failure")
                return written
            return self.handle.write(data)

        def flush(self):
            events.append("flush")
            if failure == "flush":
                raise OSError("injected flush failure")
            self.handle.flush()

    def chmod(descriptor, mode):
        assert descriptor == descriptors[0] and events[-1] == "close"
        os.fstat(descriptor)  # The original descriptor must remain live after stream close.
        assert path.read_bytes() == b"complete fixture bytes"
        events.append("descriptor_chmod")
        if failure == "chmod":
            raise OSError("injected descriptor chmod failure")
        original_chmod(descriptor, mode)
        state["mode"] = mode

    monkeypatch.setattr(driver.os, "open", open_file)
    monkeypatch.setattr(
        driver.os, "fdopen", lambda descriptor, mode, *, closefd: File(descriptor, closefd=closefd)
    )
    monkeypatch.setattr(driver.os, "fchmod", chmod)
    return SelectedPath(), path, events, state


@pytest.mark.parametrize("mode", [0o600, 0o444, 0o555])
def test_private_creation_write_flush_and_descriptor_mode_order(tmp_path, monkeypatch, mode):
    selected, path, events, state = private_writer_fixture(tmp_path, monkeypatch)
    driver._write(selected, b"complete fixture bytes", mode)
    assert events == ["create_private", "write", "flush", "close", "descriptor_chmod"]
    assert state["mode"] == mode and path.read_bytes() == b"complete fixture bytes"


@pytest.mark.parametrize("failure", ["write", "short", "flush", "close", "chmod"])
def test_incomplete_private_write_never_grants_readonly_runtime_permissions(
    tmp_path, monkeypatch, failure
):
    selected, path, events, state = private_writer_fixture(tmp_path, monkeypatch, failure=failure)
    with pytest.raises(OSError):
        driver._write(selected, b"complete fixture bytes", 0o555)
    assert path.exists() and state["mode"] == 0o600
    assert ("descriptor_chmod" in events) is (failure == "chmod")


@pytest.mark.parametrize("mode", [0o644, 0o666, 0o777, 0o400, 0o500, -1, None, True, 384.0, "384"])
def test_invalid_final_mode_is_refused_before_creation(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(
        driver.os, "open", lambda *a, **k: pytest.fail("invalid mode created a file")
    )
    with pytest.raises(ValueError, match="final mode"):
        driver._write(tmp_path / "must-not-exist", b"data", mode)
    assert not (tmp_path / "must-not-exist").exists()


def test_private_write_has_no_path_permission_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(driver.os, "fchmod", None, raising=False)
    monkeypatch.setattr(
        driver.os, "open", lambda *a, **k: pytest.fail("unsupported mode control created a file")
    )
    with pytest.raises(ValueError, match="unavailable"):
        driver._write(tmp_path / "must-not-exist", b"data", 0o444)


def test_private_writer_never_replaces_an_existing_file(tmp_path):
    path = tmp_path / "existing"
    path.write_bytes(b"original bytes")
    before = path.stat().st_mode
    with pytest.raises(FileExistsError):
        driver._write(path, b"new bytes", 0o444)
    assert path.read_bytes() == b"original bytes" and path.stat().st_mode == before


@pytest.mark.parametrize("reader", ["identity", "runtime"])
def test_regular_to_fifo_swap_opens_nonblocking_and_is_rejected_before_read(
    tmp_path, monkeypatch, reader
):
    base = tmp_path / "base"
    path = base / "input"
    metadata = dict(
        st_dev=1,
        st_ino=2,
        st_mode=0o100600,
        st_uid=1001,
        st_gid=1000,
        st_nlink=1,
        st_size=1,
        st_mtime_ns=0,
        st_ctime_ns=0,
    )
    regular = SimpleNamespace(**metadata)
    fifo = SimpleNamespace(**{**metadata, "st_mode": 0o010600})
    opened, closed = [], []
    monkeypatch.setattr(driver, "_lstat", lambda current: regular)
    monkeypatch.setattr(driver, "_open_directory", lambda current: 44)
    monkeypatch.setattr(driver.os, "stat", lambda *a, **k: regular)

    def racing_open(name, flags, *args, **kwargs):
        # A real FIFO substituted here blocks open before fstat unless NONBLOCK is set.
        if not flags & driver._posix_flag("O_NONBLOCK"):
            raise AssertionError("simulated FIFO open would block before identity verification")
        assert flags & driver._posix_flag("O_NOFOLLOW")
        opened.append((name, flags))
        return 55

    monkeypatch.setattr(driver.os, "open", racing_open)
    monkeypatch.setattr(driver.os, "fstat", lambda descriptor: fifo)
    monkeypatch.setattr(driver.os, "fdopen", lambda *a, **k: pytest.fail("changed FIFO was read"))
    monkeypatch.setattr(driver.os, "close", closed.append)
    with pytest.raises(ValueError, match="changed before"):
        if reader == "identity":
            driver.read_regular(path, owner=1001)
        else:
            driver.read_runtime_file(base, path)
    assert len(opened) == 1
    assert closed == ([55] if reader == "identity" else [55, 44])


def runtime_fixture(tmp_path):
    base = tmp_path / "selected"
    stdlib = base / "lib/python3.13"
    libpl = stdlib / "config-3.13-x86_64-linux-gnu"
    for directory in (base / "bin", libpl):
        directory.mkdir(parents=True)
    files = {
        "bin/python3.13": b"fixture, never executed",
        "lib/python3.13/os.py": b"VALUE = 1\n",
        "lib/python3.13/sysconfig.py": b"# fixture\n",
        "lib/python3.13/config-3.13-x86_64-linux-gnu/libpython3.13.so": b"linker fixture",
        "lib/libpython3.13.so.1.0": b"mapped fixture",
    }
    for name, data in files.items():
        (base / name).write_bytes(data)
    variables = {
        "LIBPL": str(libpl),
        "LIBDIR": str(base / "lib"),
        "LDVERSION": "3.13",
        "LDLIBRARY": "libpython3.13.so",
        "INTEGER": 3,
    }
    (stdlib / "_sysconfigdata_fixture.py").write_text("build_time_vars = " + repr(variables) + "\n")
    selected = {
        "version": [3, 13, 18, "final", 0],
        "abiflags": "",
        "soabi": "cpython-313-x86_64-linux-gnu",
        "prefix": str(base),
        "base_prefix": str(base),
        "executable": str(base / "bin/python3.13"),
        "base_executable": str(base / "bin/python3.13"),
        "stdlib": str(stdlib),
        "sysconfig": str(stdlib / "sysconfig.py"),
        "ldversion": "3.13",
        "ldlibrary": "libpython3.13.so",
        "libpl": str(libpl),
        "sys_path": [str(stdlib)],
        "python_maps": [],
    }
    return base, selected


def portable_reader(original, entry):
    """Only regular fixture bytes; Linux descriptor resolver has separate mock controls."""
    selected = entry.resolve(strict=True)
    if not selected.is_relative_to(original):
        raise ValueError("fixture source escapes base")
    data, info = driver.read_regular(selected)
    return data, info, selected


def staged_identity(selected, staged):
    old = selected["base_prefix"]
    result = deepcopy(selected)
    for key in (
        "prefix",
        "base_prefix",
        "executable",
        "base_executable",
        "stdlib",
        "sysconfig",
        "libpl",
    ):
        result[key] = str(staged / Path(selected[key]).relative_to(old))
    result["sys_path"] = [result["stdlib"]]
    result["python_maps"] = [str(staged / "lib/libpython3.13.so.1.0")]
    return result


def test_fresh_copy_normalizes_only_fixture_copies_and_records_literal_transforms(
    tmp_path, monkeypatch
):
    original, selected = runtime_fixture(tmp_path)
    originals = {
        path: (path.read_bytes(), path.stat().st_mode)
        for path in original.rglob("*")
        if path.is_file()
    }
    for relative in (
        "lib/python3.13/site-packages/old.py",
        "lib/python3.13/sitecustomize.py",
        "lib/python3.13/old.pth",
        "lib/python3.13/__pycache__/old.pyc",
        "lib/python313.zip",
    ):
        path = original / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("raise AssertionError('must never execute')\n")
    monkeypatch.setattr(driver, "read_runtime_file", portable_reader)
    staged = tmp_path / "private-base"
    records = driver.copy_base(original, staged)
    assert all(
        path.read_bytes() == data and path.stat().st_mode == mode
        for path, (data, mode) in originals.items()
    )
    assert not (staged / "lib/python3.13/site-packages").exists()
    assert not list(staged.rglob("*.pth")) and not list(staged.rglob("*.pyc"))
    assert not list(staged.rglob("python313.zip"))
    config = next(row for row in records if "_sysconfigdata" in row["path"])
    assert config["source_sha256"] != config["staged_sha256"]
    assert {row["key"] for row in config["literal_sysconfig_transforms"]} == {"LIBPL", "LIBDIR"}
    assert all(row["staged_mode"] in {0o444, 0o555} for row in records if row["kind"] == "file")
    assert all(
        row["staged_mode"] in {0o700, 0o755} for row in records if row["kind"] == "directory"
    )
    assert driver.validate_selected(selected, "3.13") == original
    driver.validate_staged(selected, staged_identity(selected, staged), staged)
    with pytest.raises(ValueError, match="fresh"):
        driver.copy_base(original, staged)


def test_existing_venv_is_never_copied(tmp_path):
    original, selected = runtime_fixture(tmp_path)
    (original / "pyvenv.cfg").write_text("home = /outside")
    with pytest.raises(ValueError, match="existing venv"):
        driver.validate_selected(selected, "3.13")
    with pytest.raises(ValueError, match="base source"):
        driver.copy_base(original, tmp_path / "new")


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", [3, 13, 17, "final", 0]),
        ("soabi", "different"),
        ("executable", "/old/cache/python"),
        ("sys_path", ["/opt/hostedtoolcache/old/lib/python3.13"]),
        ("sys_path", ["/usr/lib/python3.13"]),
        ("python_maps", ["/usr/lib/libpython3.13.so"]),
        ("libpl", "/outside/config-3.13"),
    ],
)
def test_relocation_patch_abi_search_map_and_linker_mismatches_fail_closed(
    tmp_path, monkeypatch, field, value
):
    original, selected = runtime_fixture(tmp_path)
    monkeypatch.setattr(driver, "read_runtime_file", portable_reader)
    staged = tmp_path / "staged"
    driver.copy_base(original, staged)
    observed = staged_identity(selected, staged)
    observed[field] = value
    with pytest.raises(ValueError):
        driver.validate_staged(selected, observed, staged)


def test_config_rebasing_never_executes_nonliteral_code(tmp_path):
    with pytest.raises(ValueError, match="unsupported"):
        driver._rebase_sysconfig(
            Path("_sysconfigdata_fixture.py"),
            b"raise AssertionError('never execute')\nbuild_time_vars={}\n",
            tmp_path / "old",
            tmp_path / "new",
        )
    with pytest.raises(ValueError):
        driver._rebase_sysconfig(
            Path("_sysconfigdata_fixture.py"),
            b"build_time_vars=execute()\n",
            tmp_path / "old",
            tmp_path / "new",
        )


def test_all_private_ancestors_are_checked_with_mocked_untrusted_mode(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    original = Path.lstat

    def metadata(path):
        value = original(path)
        return SimpleNamespace(st_mode=(0o40777 if path == root.parent else 0o40755), st_uid=0)

    monkeypatch.setattr(driver, "_lstat", metadata)
    with pytest.raises(ValueError, match="ancestor"):
        driver.trusted_directory(root)


@pytest.mark.parametrize("mutation", ["oversize", "hardlink"])
def test_source_regular_capture_refuses_bounds_and_aliases(tmp_path, monkeypatch, mutation):
    path = tmp_path / "input"
    path.write_bytes(b"input")
    if mutation == "oversize":
        with pytest.raises(ValueError, match="regular"):
            driver.read_regular(path, maximum=1)
    else:
        original = Path.lstat

        def metadata(selected):
            value = original(selected)
            return SimpleNamespace(
                st_mode=value.st_mode, st_nlink=2, st_size=value.st_size, st_uid=0
            )

        monkeypatch.setattr(driver, "_lstat", metadata)
        with pytest.raises(ValueError, match="regular"):
            driver.read_regular(path)


def test_only_four_approved_data_files_are_selected_not_authority_state(tmp_path, monkeypatch):
    private = tmp_path / "private"
    for relative in (
        *driver.EXPORTS,
        "collector/pki/key.pem",
        "collector/state/authority.db",
        "base/bin/python",
        "collector/state/catalog.pinned.json",
    ):
        path = private / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixed fixture data")
    real_read = driver.read_regular

    def read(path, *, owner, maximum):
        assert owner == 0
        return real_read(path, maximum=maximum)

    monkeypatch.setattr(driver, "read_regular", read)
    selected = driver.evidence_files(private)
    assert set(selected) == {
        "preflight.json",
        "junit.xml",
        "protected-runtime.json",
        "driver-provenance.json",
    }
    assert not any("key" in name or "db" in name or "pin" in name for name in selected)


def test_export_bounds_and_fresh_destination_are_enforced(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    (private / "preflight.json").write_bytes(b"1234")
    monkeypatch.setattr(driver, "MAX_EVIDENCE", 3)
    real_read = driver.read_regular
    monkeypatch.setattr(
        driver, "read_regular", lambda path, *, owner, maximum: real_read(path, maximum=maximum)
    )
    with pytest.raises(ValueError, match="regular"):
        driver.evidence_files(private)
    with pytest.raises(ValueError, match="separate"):
        driver.export_evidence(private, private / "public", 1001, 1000)


@pytest.mark.parametrize(
    "collector_status,export_fails,expected",
    [(0, False, 0), (7, False, 7), (7, True, 7), (0, True, 1)],
)
@pytest.mark.parametrize("preflight_mismatch", [False, True])
@pytest.mark.parametrize(
    "source_uid,runner_uid,runner_gid", [(501, 501, 20), (1001, 1001, 1000), (0, 1001, 0)]
)
def test_driver_uses_empty_probe_env_fresh_venv_and_preserves_collector_failures(
    tmp_path,
    monkeypatch,
    collector_status,
    export_fails,
    expected,
    preflight_mismatch,
    source_uid,
    runner_uid,
    runner_gid,
    owner_refusal=False,
):
    original, selected = runtime_fixture(tmp_path)

    class SourcePath(type(tmp_path)):
        # Model only this argument's owner; pathlib/pytest retain the real host OS.
        def stat(self, *args, **kwargs):
            actual = super().stat(*args, **kwargs)
            fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith("st_")}
            return SimpleNamespace(**{**fields, "st_uid": source_uid, "st_gid": runner_gid})

    source = SourcePath(tmp_path / "source")
    source.mkdir()
    identity = tmp_path / "identity.json"
    identity.write_text(json.dumps(selected))
    private = tmp_path / "private"
    args = SimpleNamespace(
        source=source,
        identity=identity,
        private_root=private,
        revision="a" * 40,
        expected_minor="3.13",
        runner_uid=runner_uid,
        runner_gid=runner_gid,
        export=tmp_path / "export",
    )
    monkeypatch.setattr(driver, "verify_bootstrap", lambda: None)
    monkeypatch.setattr(driver, "trusted_directory", lambda path: None)
    real_read = driver.read_regular

    def read(path, **kwargs):
        if path == identity:
            assert kwargs["owner"] == runner_uid
            return path.read_bytes(), SimpleNamespace(st_uid=runner_uid, st_gid=runner_gid)
        return real_read(path, **kwargs)

    monkeypatch.setattr(driver, "read_regular", read)
    monkeypatch.setattr(driver, "read_runtime_file", portable_reader)
    monkeypatch.setattr(driver, "audit_loader_routes", lambda *a: [{"fixture_metadata": "audited"}])
    commands = []

    def invoke(command, *, env, cwd, capture=False):
        commands.append((list(map(str, command)), dict(env), cwd))
        if command[:2] == ["/usr/bin/git", "rev-parse"]:
            return SimpleNamespace(stdout="a" * 40)
        if command[:2] == ["/usr/bin/git", "status"]:
            return SimpleNamespace(stdout="")
        if "-c" in command:
            observed = staged_identity(selected, private / "base")
            if preflight_mismatch:
                observed["version"][2] -= 1
            return SimpleNamespace(stdout=json.dumps(observed))
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(driver, "run", invoke)
    final = []
    monkeypatch.setattr(
        driver.subprocess,
        "run",
        lambda command, **kwargs: (
            final.append((command, kwargs)) or SimpleNamespace(returncode=collector_status)
        ),
    )

    def export(*args):
        if export_fails:
            raise OSError("fixture export failure")
        return []

    monkeypatch.setattr(driver, "export_evidence", export)
    assert driver.drive(args) == (1 if preflight_mismatch or owner_refusal else expected)
    if owner_refusal:
        assert not commands and not final
        assert json.loads((private / "driver-provenance.json").read_text())["failure_reason"] == (
            "source checkout owner differs from explicit runner"
        )
        return
    probe = next(row for row in commands if "-c" in row[0])
    assert probe[1] == {} and probe[0][1:4] == ["-I", "-S", "-B"]
    if preflight_mismatch:
        assert not final and not any("venv" in row[0] or "pip" in row[0] for row in commands)
        assert json.loads((private / "preflight.json").read_text())["passed"] is False
        return
    assert any(row[0][-3:] == ["-m", "venv", str(private / "collector-env")] for row in commands)
    assert any("--require-hashes" in row[0] for row in commands)
    assert "LD_LIBRARY_PATH" not in final[0][1]["env"]
    assert final[0][1]["env"]["SUDO_UID"] == str(source.stat().st_uid)
    assert final[0][0][-2:] == ["--workspace", str(private / "collector")]


def test_foreign_source_owner_is_refused_before_git_probe_or_collector(tmp_path, monkeypatch):
    test_driver_uses_empty_probe_env_fresh_venv_and_preserves_collector_failures(
        tmp_path,
        monkeypatch,
        collector_status=0,
        export_fails=False,
        expected=0,
        preflight_mismatch=False,
        source_uid=502,
        runner_uid=501,
        runner_gid=20,
        owner_refusal=True,
    )


def test_production_collector_contract_is_not_relaxed():
    assert len(collector.REQUIRED_POSITIVES) == 15
    assert "test_native_denial_cancel_revocation_restart_and_durable_consumption" in (
        collector.REQUIRED_POSITIVES
    )
    assert set(driver.EXPORTS.values()) == {
        "preflight.json",
        "driver-provenance.json",
        "junit.xml",
        "protected-runtime.json",
    }
    assert "site-packages" in driver.EXCLUDED_DIRS and "dist-packages" in driver.EXCLUDED_DIRS
    assert "_socket" in driver.PROBE and "python_maps" in driver.PROBE


def test_copy_rejects_an_escaping_resolved_source_before_reading_it(tmp_path, monkeypatch):
    base, _ = runtime_fixture(tmp_path)
    selected = base / "bin/python3.13"
    resolve = driver._resolve
    monkeypatch.setattr(
        driver,
        "_resolve",
        lambda path, *a, **k: tmp_path / "outside" if path == selected else resolve(path, *a, **k),
    )
    monkeypatch.setattr(driver, "read_runtime_file", lambda *a: pytest.fail("escaped file read"))
    with pytest.raises(ValueError, match="escapes"):
        driver.copy_base(base, tmp_path / "staged")


def test_copy_rejects_directory_aliases(tmp_path, monkeypatch):
    base, _ = runtime_fixture(tmp_path)
    alias = base / "directory-alias"
    alias.mkdir()
    original = Path.lstat
    monkeypatch.setattr(
        driver,
        "_lstat",
        lambda path: SimpleNamespace(st_mode=0o120777) if path == alias else original(path),
    )
    monkeypatch.setattr(driver, "read_runtime_file", portable_reader)
    with pytest.raises(ValueError, match="directory aliases"):
        driver.copy_base(base, tmp_path / "staged")


@pytest.mark.parametrize(
    "uid,mode,current",
    [
        (1001, 0o100555, "distro"),
        (0, 0o100777, "distro"),
        (0, 0o100555, "cache"),
        (0, 0o120777, "distro"),
    ],
)
def test_bootstrap_identity_refuses_runner_owned_writable_or_cache_binary(
    tmp_path, uid, mode, current
):
    expected = tmp_path / "distro"
    with pytest.raises(ValueError, match="distro Python"):
        driver._verify_bootstrap_identity(
            tmp_path / current, expected, SimpleNamespace(st_uid=uid, st_mode=mode)
        )
    driver._verify_bootstrap_identity(
        expected, expected, SimpleNamespace(st_uid=0, st_mode=0o100555)
    )


def test_descriptor_alias_reader_rejects_outside_target_without_opening_it(tmp_path, monkeypatch):
    base, _ = runtime_fixture(tmp_path)
    monkeypatch.setattr(driver, "_open_directory", lambda path: 42)
    monkeypatch.setattr(driver.os, "stat", lambda *a, **k: SimpleNamespace(st_mode=0o120777))
    monkeypatch.setattr(driver.os, "readlink", lambda *a, **k: str(tmp_path / "outside.py"))
    monkeypatch.setattr(driver.os, "close", lambda fd: None)
    monkeypatch.setattr(driver.os, "open", lambda *a, **k: pytest.fail("outside alias opened"))
    with pytest.raises(ValueError):
        driver.read_runtime_file(base, base / "bin/python3.13")


def test_export_fresh_directory_and_runner_owner_are_required(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "_open_directory", lambda path: 42)
    monkeypatch.setattr(driver.os, "close", lambda fd: None)
    monkeypatch.setattr(driver.os, "fstat", lambda fd: SimpleNamespace(st_uid=999))
    monkeypatch.setattr(driver.os, "mkdir", lambda *a, **k: pytest.fail("foreign parent used"))
    with pytest.raises(ValueError, match="runner"):
        driver.export_evidence(tmp_path / "private", tmp_path / "export", 1001, 1000)
    monkeypatch.setattr(driver.os, "fstat", lambda fd: SimpleNamespace(st_uid=1001))

    def exists(*args, **kwargs):
        raise FileExistsError("already used")

    monkeypatch.setattr(driver.os, "mkdir", exists)
    with pytest.raises(FileExistsError):
        driver.export_evidence(tmp_path / "private", tmp_path / "export", 1001, 1000)


def test_export_refuses_a_resolved_approved_name_alias_to_authority_data(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    source = private / "preflight.json"
    source.write_text("{}")
    authority = private / "key.pem"
    authority.write_text("synthetic authority data, never export")
    resolve = driver._resolve
    monkeypatch.setattr(
        driver,
        "_resolve",
        lambda path, *a, **k: authority if path == source else resolve(path, *a, **k),
    )
    monkeypatch.setattr(driver, "read_regular", lambda *a, **k: pytest.fail("aliased data read"))
    with pytest.raises(ValueError, match="escapes"):
        driver.evidence_files(private)


def test_export_uses_fixed_relative_names_and_verifies_public_data_modes(tmp_path, monkeypatch):
    fields = dict(
        st_dev=1,
        st_ino=1,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_size=0,
        st_mtime_ns=0,
        st_ctime_ns=0,
        st_mode=0o40700,
    )
    table = {
        1: SimpleNamespace(**{**fields, "st_uid": 1001}),
        2: SimpleNamespace(**fields),
        3: SimpleNamespace(**{**fields, "st_mode": 0o100600}),
    }
    opened = []
    monkeypatch.setattr(driver, "_open_directory", lambda path: 1)
    monkeypatch.setattr(driver, "evidence_files", lambda path: {"preflight.json": b"{}"})
    monkeypatch.setattr(driver.os, "O_DIRECTORY", 0x10000, raising=False)
    monkeypatch.setattr(driver.os, "O_NOFOLLOW", 0x20000, raising=False)
    monkeypatch.setattr(driver.os, "mkdir", lambda *a, **k: None)

    def open_file(name, flags, *args, **kwargs):
        opened.append((name, flags, kwargs["dir_fd"]))
        return 2 if flags & driver.os.O_DIRECTORY else 3

    monkeypatch.setattr(driver.os, "open", open_file)
    monkeypatch.setattr(driver.os, "fstat", lambda fd: table[fd])
    monkeypatch.setattr(driver.os, "stat", lambda *a, **k: table[2])
    monkeypatch.setattr(
        driver.os,
        "fchown",
        lambda fd, uid, gid: table[fd].__dict__.update(st_uid=uid, st_gid=gid),
        raising=False,
    )
    monkeypatch.setattr(
        driver.os,
        "fchmod",
        lambda fd, mode: table[fd].__dict__.update(st_mode=(table[fd].st_mode & 0o170000) | mode),
        raising=False,
    )
    monkeypatch.setattr(driver.os, "close", lambda fd: None)

    class DataFile(io.BytesIO):
        def fileno(self):
            return 3

    monkeypatch.setattr(driver.os, "fdopen", lambda *a, **k: DataFile())
    assert driver.export_evidence(tmp_path / "private", tmp_path / "export", 1001, 1000) == [
        "preflight.json"
    ]
    assert [row[0] for row in opened] == ["export", "preflight.json"]
    assert opened[1][1] & driver.os.O_EXCL and opened[1][1] & driver.os.O_NOFOLLOW
    assert table[2].st_uid == table[3].st_uid == 1001
    assert table[2].st_mode & 0o777 == 0o755 and table[3].st_mode & 0o777 == 0o644


def elf_fixture(*, search="$ORIGIN", needed="libpython3.13.so.1.0", extra_tag=None):
    """Metadata-only ELF with no executable instructions; never execute this fixture."""
    strings = b"\0" + needed.encode() + b"\0" + search.encode() + b"\0"
    string_offset, dynamic_offset = 512, 256
    entries = [
        (5, 0x400000 + string_offset),
        (10, len(strings)),
        (1, 1),
        (29, len(needed.encode()) + 2),
    ]
    if extra_tag is not None:
        entries.append((extra_tag, 1))
    entries.append((0, 0))
    data = bytearray(string_offset + len(strings))
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        2,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        120,
        2,
        6,
        dynamic_offset,
        0x400000 + dynamic_offset,
        0,
        len(entries) * 16,
        len(entries) * 16,
        8,
    )
    for index, entry in enumerate(entries):
        struct.pack_into("<qQ", data, dynamic_offset + index * 16, *entry)
    data[string_offset:] = strings
    return bytes(data)


def test_elf_metadata_is_inspected_without_running_loader_or_binary():
    result = driver.elf_routes(elf_fixture())
    assert result == {
        "interpreter": None,
        "needed": ["libpython3.13.so.1.0"],
        "search": ["$ORIGIN"],
    }
    with pytest.raises(ValueError, match="plugins"):
        driver.elf_routes(elf_fixture(extra_tag=0x6FFFFEFC))
    with pytest.raises(ValueError, match="truncated"):
        driver.elf_routes(elf_fixture()[:180])


@pytest.mark.parametrize("unsafe", [False, True])
def test_writable_cache_elf_routes_are_refused_before_the_first_runtime_exec(
    tmp_path, monkeypatch, unsafe
):
    staged = tmp_path / "private-base"
    executable = staged / "bin/python3.13"
    executable.parent.mkdir(parents=True)
    cache = tmp_path / "writable-cache"
    cache.mkdir()
    executable.write_bytes(
        elf_fixture(search="$ORIGIN/../../writable-cache" if unsafe else "$ORIGIN")
    )
    real_read = driver.read_regular
    monkeypatch.setattr(driver, "read_regular", lambda path, *, owner: real_read(path))
    checked = []

    def require_trusted(path):
        checked.append(path)
        if path == cache:
            raise ValueError("untrusted mutable loader route")

    monkeypatch.setattr(driver, "trusted_directory", require_trusted)
    monkeypatch.setattr(
        driver.subprocess, "run", lambda *a, **k: pytest.fail("ELF executed during inspection")
    )
    records = [{"kind": "file", "path": "bin/python3.13"}]
    if unsafe:
        with pytest.raises(ValueError, match="untrusted"):
            driver.audit_loader_routes(staged, executable, records)
    else:
        assert driver.audit_loader_routes(staged, executable, records)[0]["search"] == ["$ORIGIN"]
    assert checked


@pytest.mark.parametrize(
    "search,needed",
    [
        ("relative", "libpython.so"),
        ("$UNKNOWN", "libpython.so"),
        ("$ORIGIN", "relative/library.so"),
    ],
)
def test_unqualified_elf_lookup_routes_never_reach_execution(tmp_path, monkeypatch, search, needed):
    staged = tmp_path / "private-base"
    executable = staged / "bin/python3.13"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(elf_fixture(search=search, needed=needed))
    real_read = driver.read_regular
    monkeypatch.setattr(driver, "read_regular", lambda path, *, owner: real_read(path))
    monkeypatch.setattr(driver, "trusted_directory", lambda path: None)
    with pytest.raises(ValueError, match="not qualified"):
        driver.audit_loader_routes(staged, executable, [{"kind": "file", "path": "bin/python3.13"}])


@pytest.mark.parametrize(
    "relative,expected",
    [
        ("bin/python3.13", "$ORIGIN/../lib"),
        ("lib/libpython3.13.so.1.0", "$ORIGIN"),
        ("lib/python3.13/lib-dynload/_ssl.so", "$ORIGIN/../.."),
    ],
)
def test_measured_elf_route_relocation_changes_only_the_existing_string_slot(
    tmp_path, relative, expected
):
    original, staged = tmp_path / "original", tmp_path / "private-base"
    compiled = Path("/opt/hostedtoolcache/Python/3.13.18/x64")
    old = (compiled / "lib").as_posix()
    source = elf_fixture(search=old)
    relocated, changes = driver.relocate_runpaths(
        Path(relative), source, original, staged, compiled
    )
    assert driver.elf_routes(source)["search"] == [old]
    assert driver.elf_routes(relocated)["search"] == [expected]
    assert driver.elf_routes(source)["needed"] == driver.elf_routes(relocated)["needed"]
    assert len(source) == len(relocated) and len(changes) == 1
    change = changes[0]
    assert change["from"] == old and change["to"] == expected
    assert source[: change["offset"]] == relocated[: change["offset"]]
    end = change["offset"] + change["slot_bytes"]
    assert source[end:] == relocated[end:]


def test_unknown_or_mixed_elf_routes_are_not_guessed_or_blanket_rewritten(tmp_path):
    compiled = Path("/opt/hostedtoolcache/Python/3.13.18/x64")
    old = (compiled / "lib").as_posix() + ":/unreviewed/lib"
    source = elf_fixture(search=old)
    relocated, changes = driver.relocate_runpaths(
        Path("bin/python3.13"), source, tmp_path / "original", tmp_path / "new", compiled
    )
    assert relocated == source and changes == []


def test_elf_slot_growth_is_refused_without_changing_binary_layout(tmp_path):
    original, staged = tmp_path / "o", tmp_path / "new"
    source = elf_fixture(search=(original / "lib").as_posix())
    relative = Path("/".join(["deep"] * 100)) / "python"
    with pytest.raises(ValueError, match="does not fit"):
        driver.relocate_runpaths(relative, source, original, staged)


def test_shared_dependency_string_cannot_be_modified_by_route_relocation(tmp_path):
    compiled = Path("/opt/hostedtoolcache/Python/3.13.18/x64")
    source = bytearray(elf_fixture(search=(compiled / "lib").as_posix()))
    # Force DT_NEEDED to share the route's string slot: changing it would change ABI/loading.
    struct.pack_into("<qQ", source, 256 + 2 * 16, 1, len("libpython3.13.so.1.0") + 2)
    with pytest.raises(ValueError, match="unrelated loader identity"):
        driver.relocate_runpaths(
            Path("bin/python3.13"), bytes(source), tmp_path / "old", tmp_path / "new", compiled
        )
