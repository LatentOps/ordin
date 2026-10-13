"""Explicit trusted scanner selection and bounded subprocesses; default is offline."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest as core_digest
from ordin.assurance._files import directory_entries, read_scoped_file, _directory, _windows_handle
from ordin.assurance._json import digest, validate
from ordin.assurance.host import HostApproval, HostConstraintAssessment, HostEvidenceSource
from ordin.assurance.inventory import AuthorizedRepository
from ordin.assurance.models import ApprovedSecurityProfile, JsonRecord

from ._validation import loads
from .importer import ImportScope, import_codex_json
from ._suspended_process import launch_managed_process


@dataclass(frozen=True)
class ScannerSelection:
    """Operator-owned installed runtime/entrypoint paths; no PATH/npm lookup."""

    executable: Path
    executable_sha256: str
    expected_cli_version: str
    trusted_cwd: Path
    private_state_root: Path
    entrypoint: Path | None = None
    entrypoint_sha256: str | None = None
    expected_plugin_version: str | None = None
    timeout_seconds: float = 60
    max_output_bytes: int = 1_048_576
    support_executables: tuple[tuple[Path, str], ...] = ()

    def __post_init__(self):
        for path in (self.executable, self.trusted_cwd, self.private_state_root):
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError("scanner paths must be absolute host selections")
        if self.executable.suffix.lower() in {".cmd", ".bat", ".ps1"}:
            raise ValueError(
                "scanner shell launchers are unsupported; select native runtime and pinned entrypoint"
            )
        validate(
            "assurance_authority_ref",
            {"authority_id": "scanner", "boundary_digest": self.executable_sha256},
        )
        if self.entrypoint is not None:
            if (
                not isinstance(self.entrypoint, Path)
                or not self.entrypoint.is_absolute()
                or self.entrypoint_sha256 is None
            ):
                raise ValueError("scanner entrypoint requires a protected absolute path and digest")
            validate(
                "assurance_authority_ref",
                {"authority_id": "entrypoint", "boundary_digest": self.entrypoint_sha256},
            )
        elif self.entrypoint_sha256 is not None:
            raise ValueError("unexpected scanner entrypoint digest")
        if (
            not isinstance(self.expected_cli_version, str)
            or not self.expected_cli_version
            or len(self.expected_cli_version) > 128
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+", self.expected_cli_version)
        ):
            raise ValueError("scanner version must be explicitly pinned")
        if (
            type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 8_388_608
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 3600
        ):
            raise ValueError("scanner resource limits invalid")
        directory_entries(self.trusted_cwd, maximum=256)
        directory_entries(self.private_state_root, maximum=256)
        if not isinstance(self.support_executables, tuple) or len(self.support_executables) > 8:
            raise ValueError("scanner helper selection must be bounded")
        for path, pin in self.support_executables:
            if (
                not isinstance(path, Path)
                or not path.is_absolute()
                or path.suffix.lower() in {".cmd", ".bat", ".ps1"}
            ):
                raise ValueError("scanner helper requires an absolute native executable")
            validate("assurance_authority_ref", {"authority_id": "helper", "boundary_digest": pin})
        if self.expected_plugin_version is not None and not re.fullmatch(
            r"[A-Za-z0-9_.+-]{1,128}", self.expected_plugin_version
        ):
            raise ValueError("invalid plugin version pin")

    def invocation(self, arguments: tuple[str, ...]) -> list[str]:
        return [
            str(self.executable),
            *([str(self.entrypoint)] if self.entrypoint else []),
            *arguments,
        ]

    @property
    def digest(self) -> str:
        return digest(
            "scanner_selection",
            {
                "executable": self.executable_sha256,
                "executable_path_digest": core_digest(str(self.executable)),
                "entrypoint": self.entrypoint_sha256,
                "entrypoint_path_digest": core_digest(str(self.entrypoint))
                if self.entrypoint
                else None,
                "version": self.expected_cli_version,
                "plugin": self.expected_plugin_version,
                "cwd_digest": core_digest(str(self.trusted_cwd)),
                "state_digest": core_digest(str(self.private_state_root)),
                "timeout": self.timeout_seconds,
                "output_limit": self.max_output_bytes,
                "helpers": [
                    (core_digest(str(path)), pin) for path, pin in self.support_executables
                ],
            },
        )


@dataclass(frozen=True)
class ScannerRun(JsonRecord):
    SCHEMA = "assurance_scanner_run"
    run_id: str
    operation: str
    status: str
    exit_code: int | None
    executable_digest: str | None
    entrypoint_digest: str | None
    invocation_digest: str
    repository_digest: str | None
    stdout_digest: str
    stderr_digest: str
    stdout_bytes: int
    stderr_bytes: int
    expected_cli_version: str
    observed_cli_version: str | None
    elapsed_ms: float
    imported_report_digest: str | None = None
    completeness: str = "unknown"
    model_or_network_enabled: bool = False
    limitations: tuple[str, ...] = (
        "Process/artifact results are advisory; no execution permission or finding confirmation is issued.",
    )

    def __post_init__(self):
        super().__post_init__()
        if (
            self.status in {"completed", "severity_violation"}
            and self.operation == "scan"
            and (self.completeness != "complete" or self.imported_report_digest is None)
        ):
            raise ValueError("scanner success requires a complete imported artifact set")


def _sha_selected(path: Path, expected: str) -> None:
    # Installed binary may exceed the source-reader's 16 MiB bound. This is a
    # host-owned executable fingerprint only; no target-derived path is used.
    from contextlib import ExitStack

    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or getattr(initial, "st_file_attributes", 0) & 0x400:
        raise ValueError("scanner executable type unsupported")
    with _directory(path.parent) as (directory, parent), ExitStack() as stack:
        if isinstance(directory, int):
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            stack.callback(os.close, descriptor)
        else:
            import msvcrt

            with ExitStack() as handles:
                handle = _windows_handle(handles, parent / path.name, directory=False)
                descriptor = getattr(msvcrt, "open_osfhandle")(
                    handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                )
                handles.pop_all()
            stack.callback(os.close, descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 134_217_728:
            raise ValueError("scanner executable type/size unsupported")
        hasher = hashlib.sha256()
        while chunk := os.read(descriptor, 65_536):
            hasher.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or hasher.hexdigest() != expected:
            raise ValueError("scanner executable changed or differs from pin")


def _outside(
    selection: ScannerSelection, repository: AuthorizedRepository, worktree_root: Path
) -> None:
    if (
        not isinstance(repository, AuthorizedRepository)
        or not isinstance(worktree_root, Path)
        or not worktree_root.is_absolute()
        or not repository.root.is_relative_to(worktree_root)
    ):
        raise ValueError("scanner target/enclosing worktree must be host selected")
    actual_worktrees = [worktree_root]
    for parent in (repository.root, *repository.root.parents):
        try:
            (parent / ".git").lstat()
        except FileNotFoundError:
            continue
        actual_worktrees.append(parent)
    for path in (
        selection.executable,
        selection.entrypoint,
        selection.trusted_cwd,
        selection.private_state_root,
        *(path for path, _ in selection.support_executables),
    ):
        if path is not None and (
            path.is_relative_to(repository.root)
            or any(path.is_relative_to(root) for root in actual_worktrees)
        ):
            raise ValueError(
                "scanner installation/cwd/state must be outside target and enclosing worktree"
            )

    # Reject linked/remote ancestor mappings before comparing lexical paths.
    directory_entries(worktree_root, maximum=4096)
    directory_entries(repository.root, maximum=4096)
    for path in (
        selection.executable.parent,
        selection.trusted_cwd,
        selection.private_state_root,
        *([selection.entrypoint.parent] if selection.entrypoint else []),
        *(path.parent for path, _ in selection.support_executables),
    ):
        directory_entries(path, maximum=4096)


_CONFIG_PATHS = (
    ".codex/config.toml",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".git/config",
    ".git/config.worktree",
    ".gitattributes",
    ".git/info/attributes",
)


def configuration_review_digest(
    selection: ScannerSelection,
    repository: AuthorizedRepository,
    *,
    worktree_root: Path,
    reviewed_files: tuple[tuple[Path, str], ...] = (),
) -> str:
    """Fingerprint configuration bytes; refuse unreviewed executable-like inputs.

    The protected host separately reviews these files and attests that its actual
    sandbox prevents repository hooks/configuration from changing execution or
    egress. A digest is a review binding, never that sandbox attestation.
    """
    _outside(selection, repository, worktree_root)
    if not isinstance(reviewed_files, tuple) or len(reviewed_files) > 64:
        raise ValueError("scanner configuration review must be bounded")
    pins = dict(reviewed_files)
    if len(pins) != len(reviewed_files) or any(
        not isinstance(p, Path) or not p.is_absolute() for p in pins
    ):
        raise ValueError("invalid scanner configuration review paths")
    captured = []
    # Project inputs are bounded to the declared and actual enclosing worktrees.
    # Ambient user/system inputs are excluded by the fresh HOME/CODEX_HOME and
    # Git environment; managed-device configuration remains broker-reviewed.
    roots = [worktree_root]
    for parent in (repository.root, *repository.root.parents):
        try:
            (parent / ".git").lstat()
        except FileNotFoundError:
            continue
        roots.append(parent)
    outer = min(roots, key=lambda path: len(path.parts))
    parents = [
        parent
        for parent in (repository.root, *repository.root.parents)
        if parent.is_relative_to(outer)
    ]
    candidates = {parent / rel for parent in parents for rel in _CONFIG_PATHS}
    for path in sorted(candidates, key=str):
        # lstat distinguishes absence from an inaccessible or linked input.
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raw = read_scoped_file(path.parent, path.name)
        pin = hashlib.sha256(raw).hexdigest()
        if pins.get(path) != pin:
            raise ValueError("scanner configuration was not separately reviewed or changed")
        captured.append((core_digest(str(path)), pin))
    if set(pins) - candidates or len(captured) != len(pins):
        raise ValueError("scanner reviewed configuration is absent or outside supported inputs")
    return digest(
        "scanner_configuration_review",
        {
            "selection": selection.digest,
            "repository": repository.repository.digest,
            "root": core_digest(str(repository.root)),
            "worktree": core_digest(str(worktree_root)),
            "configuration": captured,
            "contract": "0.2.0-isolated-api-key-standard-v1",
        },
    )


def _fresh_state(selection: ScannerSelection) -> None:
    if directory_entries(selection.private_state_root):
        raise ValueError("scanner requires a fresh private state directory")
    if os.name == "posix" and selection.private_state_root.stat().st_mode & 0o077:
        raise ValueError("scanner state must be privately permissioned")


def _environment(selection, provided: Mapping[str, str] | None = None) -> dict[str, str]:
    # No ambient API/cloud token, Python/Node preload, shell startup or Git hook
    # environment is inherited. Dependencies must be installed in the trusted runtime.
    allowed = {"SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(
        {
            "HOME": str(selection.private_state_root),
            "USERPROFILE": str(selection.private_state_root),
            "CODEX_HOME": str(selection.private_state_root / "codex-home"),
            "CODEX_SECURITY_STATE_DIR": str(selection.private_state_root),
            "TMP": str(selection.private_state_root),
            "TEMP": str(selection.private_state_root),
            "PATH": os.pathsep.join(
                dict.fromkeys(
                    str(path.parent)
                    for path in (
                        selection.executable,
                        *(p for p, _ in selection.support_executables),
                    )
                )
            ),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "diff.external",
            "GIT_CONFIG_VALUE_2": "",
        }
    )
    if provided:
        if set(provided) - {"OPENAI_API_KEY"} or any(
            not isinstance(v, str) or not v or "\x00" in v for v in provided.values()
        ):
            raise ValueError(
                "scanner environment requires separately authorized API credential only"
            )
        env.update(provided)
    return env


def _run(
    selection: ScannerSelection,
    arguments: tuple[str, ...],
    *,
    cancel: threading.Event | None = None,
    credentials: Mapping[str, str] | None = None,
):
    started = time.monotonic()
    try:
        _sha_selected(selection.executable, selection.executable_sha256)
        if selection.entrypoint:
            assert selection.entrypoint_sha256 is not None
            _sha_selected(selection.entrypoint, selection.entrypoint_sha256)
        for path, pin in selection.support_executables:
            _sha_selected(path, pin)
    except FileNotFoundError:
        return "unavailable", None, b"", b"", 0
    except (OSError, ValueError):
        return "error", None, b"", b"", 0
    stdout, stderr = bytearray(), bytearray()
    overflow = threading.Event()
    if cancel is not None and cancel.is_set():
        return "canceled", None, b"", b"", 0
    try:
        process, tree = launch_managed_process(
            selection.invocation(arguments),
            cwd=selection.trusted_cwd,
            env=_environment(selection, credentials),
            stdin=subprocess.DEVNULL,
        )
    except (OSError, ValueError):
        return "error", None, b"", b"", round((time.monotonic() - started) * 1000, 6)

    def drain(pipe, buffer):
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    break
                remaining = selection.max_output_bytes - len(buffer)
                buffer.extend(chunk[: max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    break
        finally:
            pipe.close()

    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    status = None
    try:
        while process.poll() is None:
            if overflow.is_set():
                status = "output_limit"
                break
            if cancel is not None and cancel.is_set():
                status = "canceled"
                break
            if time.monotonic() - started >= selection.timeout_seconds:
                status = "timeout"
                break
            time.sleep(0.01)
    except KeyboardInterrupt:
        status = "canceled"
    finally:
        # End descendants, including a background child after normal exit.
        try:
            tree.close()
        except OSError:
            # The owned job still closes through ProcessTree's kill-on-close
            # fallback. Unconfirmed cleanup cannot yield completed evidence.
            status = "error"
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            status = "error"
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        status = status or "error"
    if overflow.is_set():
        status = "output_limit"
    return (
        status
        or (
            "completed"
            if process.returncode in {0, 1}
            else "canceled"
            if process.returncode in {130, 143, -2, -15}
            else "incomplete"
            if process.returncode == 2
            else "error"
        ),
        process.returncode,
        bytes(stdout),
        bytes(stderr),
        round((time.monotonic() - started) * 1000, 6),
    )


def _report(
    selection,
    operation,
    status,
    code,
    out,
    err,
    elapsed,
    arguments,
    *,
    version=None,
    repository=None,
    imported=None,
    live=False,
):
    invocation = digest("scanner_invocation", [selection.digest, arguments])
    return ScannerRun(
        "scanner-run:" + invocation[:24],
        operation,
        status,
        code,
        selection.executable_sha256,
        selection.entrypoint_sha256,
        invocation,
        repository.repository.digest if repository else None,
        hashlib.sha256(out).hexdigest(),
        hashlib.sha256(err).hexdigest(),
        len(out),
        len(err),
        selection.expected_cli_version,
        version,
        elapsed,
        imported_report_digest=imported.digest if imported else None,
        completeness=imported.completeness if imported else "unknown",
        model_or_network_enabled=live,
    )


def inspect_scanner(
    selection: ScannerSelection, *, cancel: threading.Event | None = None
) -> ScannerRun:
    if not isinstance(selection, ScannerSelection):
        raise ValueError("scanner selection must be host owned")
    _fresh_state(selection)
    status, code, out, err, elapsed = _run(selection, ("--version",), cancel=cancel)
    version = None
    if status == "completed" and code == 0:
        try:
            version = out.decode("utf-8").strip()
            if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", version):
                version = None
                status = "error"
        except UnicodeError:
            status = "error"
        if status == "completed" and version != selection.expected_cli_version:
            status = "version_mismatch"
    elif status == "completed":
        status = "error"
    if status == "completed":
        # Inspect the actual installed command surface before constructing flags.
        help_status, help_code, help_out, help_err, help_elapsed = _run(
            selection, ("scan", "--help"), cancel=cancel
        )
        elapsed += help_elapsed
        if (
            help_status != "completed"
            or help_code != 0
            or any(
                flag.encode() not in help_out
                for flag in (
                    "--diff",
                    "--head",
                    "--output-dir",
                    "--auth",
                    "--provider",
                    "--mode",
                    "--json",
                )
            )
        ):
            return _report(
                selection,
                "inspect",
                help_status if help_status != "completed" else "version_mismatch",
                help_code,
                help_out,
                help_err,
                elapsed,
                ("--version", "scan", "--help"),
                version=version,
            )
        info_status, info_code, info_out, info_err, info_elapsed = _run(
            selection, ("info", "--json"), cancel=cancel
        )
        if info_status == "completed" and info_code == 0:
            try:
                info = loads(info_out)
                # Incur can return its documented full-output envelope.
                if info.get("ok") is True and isinstance(info.get("data"), dict):
                    info = info["data"]
                if (
                    info.get("cliVersion") != selection.expected_cli_version
                    or info.get("sdkVersion") != selection.expected_cli_version
                    or (
                        selection.expected_plugin_version is not None
                        and info.get("bundledPluginVersion") != selection.expected_plugin_version
                    )
                ):
                    info_status = "version_mismatch"
                if (
                    info.get("scanMcp") is not False
                    or not isinstance(info.get("configuration"), dict)
                    or info["configuration"].get("path") is not None
                ):
                    info_status = "error"
            except ValueError:
                info_status = "error"
        elif info_status == "completed":
            info_status = "error"
        status, code, out, err, elapsed = (
            info_status,
            info_code,
            info_out,
            info_err,
            elapsed + info_elapsed,
        )
    return _report(
        selection,
        "inspect",
        status,
        code,
        out,
        err,
        elapsed,
        ("--version", "scan", "--help", "info", "--json"),
        version=version,
    )


def scan_action(
    selection: ScannerSelection,
    repository: AuthorizedRepository,
    *,
    base_revision: str,
    reviewed_config_digest: str,
) -> ActionEnvelope:
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base_revision):
        raise ValueError("scanner diff base must be a pinned Git object, not a mutable ref")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", repository.repository.revision):
        raise ValueError("scanner target must be a pinned Git revision")
    validate(
        "assurance_authority_ref",
        {"authority_id": base_revision, "boundary_digest": reviewed_config_digest},
    )
    return ActionEnvelope(
        "scanner",
        "scan",
        {
            "repository": repository.repository.as_dict(),
            "selection_digest": selection.digest,
            "base_revision": base_revision,
            "config_review_digest": reviewed_config_digest,
            "upload_disclosure": "authorized source is sent to the approved OpenAI API service",
        },
        action_id="scanner-diff",
    )


def run_diff_scan(
    selection: ScannerSelection,
    repository: AuthorizedRepository,
    *,
    worktree_root: Path,
    source: HostEvidenceSource,
    profile: ApprovedSecurityProfile,
    approval: HostApproval,
    base_revision: str,
    reviewed_config_digest: str,
    isolation: HostConstraintAssessment,
    reviewed_files: tuple[tuple[Path, str], ...] = (),
    credentials: Mapping[str, str],
    cancel: threading.Event | None = None,
) -> ScannerRun:
    """Explicit host-only scan. The host must separately isolate/review runtime configuration.

    Consent binds target, executable, base and review digest; no JSON or command
    text can supply it. This wrapper does not replace a physical sandbox/process
    broker, including descendant cancellation enforcement on Windows.
    """
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(profile, ApprovedSecurityProfile)
        or not isinstance(approval, HostApproval)
    ):
        raise ValueError("live scan requires protected host/profile and actual explicit approval")
    source._check_profile(profile)
    _outside(selection, repository, worktree_root)
    if (
        configuration_review_digest(
            selection, repository, worktree_root=worktree_root, reviewed_files=reviewed_files
        )
        != reviewed_config_digest
    ):
        raise ValueError("scanner configuration review no longer matches actual inputs")
    action = scan_action(
        selection,
        repository,
        base_revision=base_revision,
        reviewed_config_digest=reviewed_config_digest,
    )
    if (
        approval.source_key != source.key
        or approval.profile_digest != profile.digest
        or approval.action_digest != core_digest(action.as_dict())
        or source.repository != repository.repository
    ):
        raise ValueError("scan consent is stale or belongs to another target/configuration")
    if (
        not isinstance(isolation, HostConstraintAssessment)
        or isolation.source_key != source.key
        or isolation.profile_digest != profile.digest
        or isolation.action_digest != core_digest(action.as_dict())
        or isolation.invariant_id != "scanner.isolation"
        or isolation.kind != "scanner_isolation"
        or isolation.status != "satisfied"
    ):
        raise ValueError("live scanner needs a current protected broker isolation assessment")
    if not credentials or set(credentials) != {"OPENAI_API_KEY"}:
        raise ValueError("approved scanner API credential is absent")
    _environment(selection, credentials)
    _fresh_state(selection)
    inspected = inspect_scanner(selection, cancel=cancel)
    if inspected.status != "completed":
        return inspected
    if selection.expected_cli_version != "0.2.0":
        raise ValueError(
            "live scanner command contract is implemented only for the inspected 0.2.0 release"
        )
    if (
        configuration_review_digest(
            selection, repository, worktree_root=worktree_root, reviewed_files=reviewed_files
        )
        != reviewed_config_digest
    ):
        raise ValueError("scanner configuration changed during inspection")
    # No target-controlled launch flags, hooks, plugin/MCP paths, custom provider
    # URLs, patch/publication or deep mode are accepted from caller strings.
    arguments = (
        "scan",
        str(repository.root),
        "--diff",
        base_revision,
        "--head",
        repository.repository.revision,
        "--mode",
        "standard",
        "--output-dir",
        str(selection.private_state_root / "scan"),
        "--auth",
        "api-key",
        "--provider",
        "openai",
        "--headless",
        "--json",
    )
    status, code, out, err, elapsed = _run(
        selection, arguments, cancel=cancel, credentials=credentials
    )
    imported = None
    if status in {"completed", "incomplete"}:
        try:
            imported = import_codex_json(
                ImportScope(
                    (selection.private_state_root / "scan").absolute(),
                    repository.repository,
                    expected_plugin_version=selection.expected_plugin_version,
                ),
                threat_model_path="threatmodel.md"
                if any(
                    e.name == "threatmodel.md"
                    for e in directory_entries(selection.private_state_root / "scan")
                )
                else None,
            )
            status = (
                "completed"
                if code == 0 and imported.conclusive_import
                else "severity_violation"
                if code == 1 and imported.conclusive_import
                else "incomplete"
            )
        except ValueError:
            status = "incomplete"
    return _report(
        selection,
        "scan",
        status,
        code,
        out,
        err,
        elapsed,
        arguments,
        version=inspected.observed_cli_version,
        repository=repository,
        imported=imported,
        live=True,
    )


def mock_scanner_run(*, exit_code: int = 0, completeness: str = "complete") -> ScannerRun:
    """Built-in offline mock; never selects or launches an external executable."""
    if exit_code not in {0, 1, 2, 130, 143} or completeness not in {
        "complete",
        "partial",
        "unknown",
    }:
        raise ValueError("unknown mock scanner state")
    status = (
        "canceled"
        if exit_code in {130, 143}
        else "incomplete"
        if exit_code == 2 or completeness != "complete"
        else "severity_violation"
        if exit_code == 1
        else "completed"
    )
    empty = hashlib.sha256(b"").hexdigest()
    invocation = digest("mock_scanner", [exit_code, completeness])
    return ScannerRun(
        "mock-scanner:" + invocation[:24],
        "mock",
        status,
        exit_code,
        None,
        None,
        invocation,
        None,
        empty,
        empty,
        0,
        0,
        "mock-v1",
        "mock-v1",
        0,
        completeness=completeness,
        model_or_network_enabled=False,
    )
