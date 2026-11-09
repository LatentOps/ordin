"""Fixed pytest catalogues over original, immutable, host-prepared snapshots."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import sysconfig
from threading import RLock
from typing import Any, Mapping
from uuid import uuid4

from ordin.action import ActionEnvelope
from ordin.adapters import ToolCallAdapter
from ordin._runtime_json import digest
from ordin.enforcement_backend import BackendValidationResult, CompilationResult, EnforcementPlan
from ordin.execution import ObservedResource
from ordin.runtime_contract import (
    FilesystemCapability,
    PrivilegeCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
    ToolCapability,
)
from ordin.runtime_observation import RuntimeEvidenceSource

from .linux_backend import ExecutorOutcome
from .managed_process import (
    LinuxProtectedProcess,
    ProtectedProcessJob,
    ProtectedProcessLimits,
    _hex,
    _private_directory,
    _sha,
    _source,
)

MAX_PROJECT_FILES = 2048
MAX_PROJECT_BYTES = 16 * 1048576
MAX_RUNTIME_FILES = 4096
MAX_RUNTIME_BYTES = 192 * 1048576
IGNORED_PROJECT = frozenset({".git", ".pytest_cache", "__pycache__", ".venv", "venv"})
FORBIDDEN_RUNTIME = frozenset({"sitecustomize.py", "usercustomize.py", ".env", ".pypirc"})


def _wire(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _capture(
    root: Path, maximum_files: int, maximum_bytes: int, *, ignored: frozenset[str] = IGNORED_PROJECT
) -> tuple[list[tuple], dict[str, bytes]]:
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError("canonical operator-selected snapshot root required")
    records: list[tuple] = []
    contents: dict[str, bytes] = {}
    count = total = 0

    def identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def visit(directory, relative, depth):
        nonlocal count, total
        if depth > 16:
            raise ValueError("snapshot nesting exceeds bound")
        before = os.fstat(directory) if type(directory) is int else directory.stat()
        records.append((relative or ".", "directory", identity(before), None))
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if entry.name in ignored:
                    continue
                count += 1
                if count > maximum_files:
                    raise ValueError("snapshot item count exceeds bound")
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            name = (relative + "/" if relative else "") + entry.name
            if len(name.encode("utf-8")) > 512 or any(ord(c) < 32 for c in name):
                raise ValueError("snapshot path is ambiguous or exceeds bound")
            info = (
                entry.stat(follow_symlinks=False)
                if type(directory) is int
                else os.stat(entry.path, follow_symlinks=False)
            )
            if stat.S_ISDIR(info.st_mode):
                if type(directory) is int:
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                    try:
                        if identity(os.fstat(child)) != identity(info):
                            raise ValueError("snapshot directory changed during traversal")
                        visit(child, name, depth + 1)
                    finally:
                        os.close(child)
                else:
                    visit(Path(entry.path), name, depth + 1)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                if total + info.st_size > maximum_bytes:
                    raise ValueError("snapshot byte count exceeds bound")
                if type(directory) is int:
                    descriptor = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                        dir_fd=directory,
                    )
                    try:
                        if identity(os.fstat(descriptor)) != identity(info):
                            raise ValueError("snapshot file changed before capture")
                        chunks = bytearray()
                        while len(chunks) <= maximum_bytes - total:
                            part = os.read(
                                descriptor, min(65536, maximum_bytes - total + 1 - len(chunks))
                            )
                            if not part:
                                break
                            chunks.extend(part)
                        if len(chunks) > maximum_bytes - total or identity(
                            os.fstat(descriptor)
                        ) != identity(info):
                            raise ValueError("snapshot file changed or exceeded bound")
                        data = bytes(chunks)
                    finally:
                        os.close(descriptor)
                else:
                    data = _source(Path(entry.path), maximum_bytes - total)
                total += len(data)
                records.append((name, "file", identity(info), hashlib.sha256(data).hexdigest()))
                contents[name] = data
            else:
                raise ValueError("snapshot must contain only regular files/directories, no links")
        after = os.fstat(directory) if type(directory) is int else directory.stat()
        if identity(before) != identity(after):
            raise ValueError("snapshot directory changed during capture")

    if sys.platform == "linux":
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            visit(descriptor, "", 0)
        finally:
            os.close(descriptor)
    else:
        # Inspection only. The executable runner refuses non-Linux platforms.
        visit(root, "", 0)
    records.sort(key=lambda row: row[0])
    return records, contents


def _tree_digest(records: list[tuple]) -> str:
    return hashlib.sha256(_wire([(r[0], r[1], r[3]) for r in records])).hexdigest()


def _copy_capture(root: Path, records: list[tuple], contents: dict[str, bytes]) -> None:
    root.mkdir(mode=0o700)
    for relative, kind, _, _ in records:
        target = root / relative
        if kind == "directory":
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as output:
                output.write(contents[relative])
                output.flush()
                os.fsync(output.fileno())
            target.chmod(0o444)
    for directory, _, _ in os.walk(root, topdown=False):
        Path(directory).chmod(0o555)


@dataclass(frozen=True, slots=True)
class PythonRuntimeCatalog:
    root: Path
    digest: str
    interpreter: Path
    interpreter_digest: str
    stdlib_virtual: str
    pytest_version: str

    def __post_init__(self) -> None:
        if type(self.root) is not type(Path()) or type(self.interpreter) is not type(Path()):
            raise ValueError("explicit runtime catalogue paths required")
        _hex(self.digest)
        _hex(self.interpreter_digest)
        if (
            not self.root.is_absolute()
            or not self.interpreter.is_absolute()
            or not self.stdlib_virtual.startswith("/")
            or ".." in Path(self.stdlib_virtual).parts
            or self.stdlib_virtual in {"/", "/scratch", "/tmp"}
            or type(self.pytest_version) is not str
            or not 1 <= len(self.pytest_version) <= 64
        ):
            raise ValueError("invalid fixed runtime catalogue")


def _catalog_manifest(root: Path) -> Path:
    _private_directory(root.parent)
    return root.parent / (root.name + ".pinned.json")


def _catalog_settings(catalog: PythonRuntimeCatalog) -> dict:
    return {
        "interpreter": str(catalog.interpreter),
        "interpreter_digest": catalog.interpreter_digest,
        "stdlib_virtual": catalog.stdlib_virtual,
        "pytest_version": catalog.pytest_version,
    }


def _runtime_source(source: Path, trusted_root: Path, maximum: int) -> bytes:
    """Read trusted stdlib file aliases; never preserve links in the private image.

    Only leaf aliases wholly within the original canonical stdlib root are
    admitted. Directory aliases, external hops, mutable/unowned source objects,
    replacement during capture, and excessive alias/depth/byte counts refuse.
    Linux opens are anchored to retained no-follow directory descriptors.
    """
    if (
        not source.is_absolute()
        or not trusted_root.is_absolute()
        or trusted_root.resolve(strict=True) != trusted_root
        or type(maximum) is not int
        or not 0 <= maximum <= MAX_RUNTIME_BYTES
    ):
        raise ValueError("canonical bounded trusted runtime source required")

    def identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def trusted(info, *, directory=False, link=False):
        expected = stat.S_ISDIR if directory else stat.S_ISLNK if link else stat.S_ISREG
        if (
            not expected(info.st_mode)
            or (not directory and info.st_nlink != 1)
            or (
                os.name == "posix"
                and (
                    info.st_uid not in {0, os.geteuid()}
                    or (not link and stat.S_IMODE(info.st_mode) & 0o022)
                )
            )
        ):
            raise ValueError("trusted immutable runtime source ownership/mode required")

    anchored = os.name == "posix"
    directories: list[tuple[int | None, Path, os.stat_result]] = []
    leaves: list[tuple[int | None, Path, os.stat_result, str | None]] = []
    descriptors = []
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_info = trusted_root.lstat()
    trusted(root_info, directory=True)
    try:
        root_fd = os.open(trusted_root, flags | os.O_DIRECTORY) if anchored else None
        if root_fd is not None:
            descriptors.append(root_fd)
            if identity(os.fstat(root_fd)) != identity(root_info):
                raise ValueError("trusted runtime root changed before capture")
        directories.append((root_fd, trusted_root, root_info))
        candidate = source
        for _ in range(9):
            if ".." in candidate.parts or not candidate.is_relative_to(trusted_root):
                raise ValueError("runtime source alias escapes trusted root")
            relative = candidate.relative_to(trusted_root)
            if not 1 <= len(relative.parts) <= 16:
                raise ValueError("runtime source nesting exceeds bound")
            parent_fd, parent_path = root_fd, trusted_root
            for part in relative.parts[:-1]:
                parent_path /= part
                if anchored:
                    parent_fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent_fd)
                    descriptors.append(parent_fd)
                    info = os.fstat(parent_fd)
                else:
                    info = parent_path.lstat()
                trusted(info, directory=True)
                directories.append((parent_fd, parent_path, info))
            name = relative.name
            before = (
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if anchored
                else candidate.lstat()
            )
            if stat.S_ISLNK(before.st_mode):
                trusted(before, link=True)
                target = os.readlink(name, dir_fd=parent_fd) if anchored else os.readlink(candidate)
                if ".." in Path(target).parts:
                    raise ValueError("runtime source alias parent traversal is unsupported")
                if len(os.fsencode(target)) > 4096:
                    raise ValueError("runtime source alias exceeds bound")
                leaves.append((parent_fd, candidate, before, target))
                resolved = Path(target) if Path(target).is_absolute() else candidate.parent / target
                candidate = Path(os.path.normpath(resolved))
                continue
            trusted(before)
            if before.st_size > maximum:
                raise ValueError("runtime source byte count exceeds bound")
            read_flags = flags | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
            descriptor = (
                os.open(name, read_flags, dir_fd=parent_fd)
                if anchored
                else os.open(candidate, read_flags)
            )
            descriptors.append(descriptor)
            captured = os.fstat(descriptor)
            # Windows path stat and descriptor stat expose different ctime
            # meanings. Compare common cross-API fields there, then retain the
            # complete descriptor identity (including ctime) across the read.
            # Qualified Linux always compares every field across both APIs.
            if (
                identity(captured) != identity(before)
                if anchored
                else identity(captured)[:-1] != identity(before)[:-1]
            ):
                raise ValueError("runtime source changed before capture")
            chunks = bytearray()
            while len(chunks) <= maximum:
                data = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
                if not data:
                    break
                chunks.extend(data)
            leaves.append((parent_fd, candidate, before, None))
            if len(chunks) > maximum or identity(os.fstat(descriptor)) != identity(captured):
                raise ValueError("runtime source changed or exceeded byte bound")
            for selected_fd, path, info, link_target in leaves:
                current = (
                    os.stat(path.name, dir_fd=selected_fd, follow_symlinks=False)
                    if anchored
                    else path.lstat()
                )
                if identity(current) != identity(info) or (
                    link_target is not None
                    and link_target
                    != (
                        os.readlink(path.name, dir_fd=selected_fd)
                        if anchored
                        else os.readlink(path)
                    )
                ):
                    raise ValueError("runtime source alias changed during capture")
            for selected_fd, path, info in directories:
                current = os.fstat(selected_fd) if selected_fd is not None else path.lstat()
                if identity(current) != identity(info):
                    raise ValueError("runtime source directory changed during capture")
            if trusted_root.resolve(strict=True) != trusted_root or identity(
                trusted_root.lstat()
            ) != identity(root_info):
                raise ValueError("trusted runtime root changed during capture")
            return bytes(chunks)
        raise ValueError("runtime source alias chain exceeds bound")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_catalog(catalog: PythonRuntimeCatalog) -> None:
    interpreter = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if catalog.interpreter != interpreter or _sha(interpreter) != catalog.interpreter_digest:
        raise ValueError("fixed test interpreter differs from pinned installation")
    records, _ = _capture(catalog.root, MAX_RUNTIME_FILES, MAX_RUNTIME_BYTES, ignored=frozenset())
    if _tree_digest(records) != catalog.digest:
        raise ValueError("fixed test runtime catalogue changed")
    if any(
        Path(row[0]).name in FORBIDDEN_RUNTIME
        or Path(row[0]).suffix in {".pth", ".pyc", ".pem", ".key", ".p12"}
        or (row[0] not in {".", "catalog.json"} and row[0].split("/")[0] not in {"stdlib", "site"})
        or stat.S_IMODE(row[2][2]) != (0o555 if row[1] == "directory" else 0o444)
        or row[2][3] != os.geteuid()
        for row in records
    ):
        raise ValueError("runtime catalogue contains prohibited bootstrap data")
    settings = json.loads(_source(catalog.root / "catalog.json", 65536))
    if settings != _catalog_settings(catalog) or catalog.stdlib_virtual != str(
        Path(sysconfig.get_path("stdlib")).resolve()
    ):
        raise ValueError("original runtime catalogue metadata differs")


def load_python_runtime_catalog(root: Path, *, operator: object) -> PythonRuntimeCatalog:
    """Reattach only after verifying the private installation pin and actual bytes.

    The owner-only sibling manifest is host installation state, never agent JSON
    or a permit. Missing/changed pins require explicit new installation; loading
    never rebuilds a tree, rewrites a manifest, or restores an execution handle.
    """
    if type(operator) is not object or sys.platform != "linux":
        raise ValueError("qualified Linux host operator required for runtime loading")
    root = Path(root).absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("canonical runtime catalogue root required")
    manifest = _catalog_manifest(root)
    descriptor = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > 65536
        ):
            raise ValueError("private owner-only runtime installation pin required")
        chunks = bytearray()
        while len(chunks) <= 65536:
            part = os.read(descriptor, min(65536, 65537 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(descriptor)

        def identity(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if len(chunks) > 65536 or identity(before) != identity(after):
            raise ValueError("runtime installation pin changed or exceeded bound")
    finally:
        os.close(descriptor)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate runtime installation pin field")
            value[key] = item
        return value

    try:
        payload = json.loads(chunks, object_pairs_hook=unique)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid bounded runtime installation pin") from exc
    if (
        type(payload) is not dict
        or set(payload)
        != {
            "schema_version",
            "root",
            "digest",
            "interpreter",
            "interpreter_digest",
            "stdlib_virtual",
            "pytest_version",
        }
        or payload["schema_version"] != "ordin.python_runtime_catalog.v1"
        or payload["root"] != str(root)
    ):
        raise ValueError("runtime installation pin scope differs")
    if any(type(value) is not str for value in payload.values()):
        raise ValueError("runtime installation pin requires exact text fields")
    catalog = PythonRuntimeCatalog(
        root,
        payload["digest"],
        Path(payload["interpreter"]),
        payload["interpreter_digest"],
        payload["stdlib_virtual"],
        payload["pytest_version"],
    )
    _verify_catalog(catalog)
    return catalog


def build_python_runtime_catalog(root: Path, *, operator: object) -> PythonRuntimeCatalog:
    """Explicit host setup: copy curated installed code, never execute .pth/plugins.

    The base interpreter is the original running trusted interpreter. This does
    not launch a selected venv to discover its code. Only explicit pytest package
    trees and standard-library source/extensions are materialized, not a whole
    host/venv directory or its credentials.
    """
    if type(operator) is not object or sys.platform != "linux":
        raise ValueError("qualified Linux host operator required for runtime staging")
    root = Path(root).absolute()
    _private_directory(root, empty=True)
    manifest = _catalog_manifest(root)
    if os.path.lexists(manifest):
        raise ValueError("runtime installation pin already exists; refuse rebuild")
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    selected: dict[str, bytes] = {}
    total = 0

    def add(relative: str, source: Path, *, standard_library: bool = False) -> None:
        nonlocal total
        if len(selected) >= MAX_RUNTIME_FILES:
            raise ValueError("runtime catalogue item count exceeds bound")
        data = (
            _runtime_source(source, stdlib, MAX_RUNTIME_BYTES - total)
            if standard_library
            else _source(source, MAX_RUNTIME_BYTES - total)
        )
        total += len(data)
        selected[relative] = data

    excluded = IGNORED_PROJECT | {
        "site-packages",
        "dist-packages",
        "test",
        "tests",
        "ensurepip",
        "idlelib",
        "tkinter",
        "turtledemo",
    }
    for directory, dirs, files in os.walk(stdlib, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in excluded)
        for name in sorted(files):
            source = Path(directory) / name
            if source.suffix in {".py", ".so"} and name not in FORBIDDEN_RUNTIME:
                add(
                    "stdlib/" + source.relative_to(stdlib).as_posix(), source, standard_library=True
                )
    packages: tuple[tuple[str, str], ...] = (
        ("pytest", "pytest"),
        ("_pytest", "pytest"),
        ("pluggy", "pluggy"),
        ("packaging", "packaging"),
        ("iniconfig", "iniconfig"),
        ("pygments", "pygments"),
    )
    if sys.version_info < (3, 11):
        packages += (("exceptiongroup", "exceptiongroup"), ("tomli", "tomli"))
    for module, distribution in packages:
        installed = importlib.metadata.distribution(distribution)
        source = Path(str(installed.locate_file(module))).resolve()
        if source.is_file():
            add("site/" + module + ".py", source)
            continue
        if not source.is_dir():
            source = Path(str(installed.locate_file(module + ".py"))).resolve()
            add("site/" + module + ".py", source)
            continue
        for directory, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in excluded)
            for name in sorted(files):
                item = Path(directory) / name
                if name in FORBIDDEN_RUNTIME or item.suffix in {
                    ".pth",
                    ".pyc",
                    ".pem",
                    ".key",
                    ".p12",
                }:
                    continue
                add("site/" + module + "/" + item.relative_to(source).as_posix(), item)
    interpreter = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    settings = {
        "interpreter": str(interpreter),
        "interpreter_digest": _sha(interpreter),
        "stdlib_virtual": str(stdlib),
        "pytest_version": importlib.metadata.version("pytest"),
    }
    selected["catalog.json"] = _wire(settings)
    for relative, data in selected.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as output:
            output.write(data)
        target.chmod(0o444)
    records, _ = _capture(root, MAX_RUNTIME_FILES, MAX_RUNTIME_BYTES, ignored=frozenset())
    for directory, _, _ in os.walk(root, topdown=False):
        Path(directory).chmod(0o555)
    catalog = PythonRuntimeCatalog(
        root,
        _tree_digest(records),
        interpreter,
        settings["interpreter_digest"],
        str(stdlib),
        settings["pytest_version"],
    )
    _verify_catalog(catalog)
    descriptor = os.open(
        manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(
            _wire(
                {
                    "schema_version": "ordin.python_runtime_catalog.v1",
                    "root": str(root),
                    "digest": catalog.digest,
                    **_catalog_settings(catalog),
                }
            )
        )
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return load_python_runtime_catalog(root, operator=operator)


@dataclass(frozen=True, slots=True)
class TestRoute:
    __test__ = False
    test_id: str
    project_root: Path
    selectors: tuple[str, ...]
    runtime: PythonRuntimeCatalog
    tool_runtime: str = "ordin-owned"
    tool_name: str = "run_tests"

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) is None
                for value in (self.test_id, self.tool_runtime, self.tool_name)
            )
            or not isinstance(self.project_root, Path)
            or not self.project_root.is_absolute()
            or type(self.runtime) is not PythonRuntimeCatalog
            or type(self.selectors) is not tuple
            or not 1 <= len(self.selectors) <= 16
            or len(set(self.selectors)) != len(self.selectors)
        ):
            raise ValueError("exact fixed test route and catalogue required")
        for value in self.selectors:
            if (
                type(value) is not str
                or len(value) > 256
                or re.fullmatch(r"[A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_]+)*", value) is None
                or value.startswith(("/", "-"))
                or ".." in value.split("::")[0].split("/")
            ):
                raise ValueError("test selectors must be fixed relative Python node IDs")
        if any(
            left == right or left.is_relative_to(right)
            for left, right in (
                (self.project_root, self.runtime.root),
                (self.runtime.root, self.project_root),
            )
        ):
            raise ValueError("test project and trusted runtime must not overlap")
        virtual = (self.project_root, self.runtime.root, Path(self.runtime.stdlib_virtual))
        if sys.platform == "linux" and (
            any(path.resolve(strict=True) != path for path in virtual[:2])
            or any(
                a == b or a.is_relative_to(b) or b.is_relative_to(a)
                for i, a in enumerate(virtual)
                for b in virtual[i + 1 :]
            )
            or any(
                a == Path("/")
                or a == Path("/tmp")
                or a.is_relative_to("/scratch")
                or Path("/scratch").is_relative_to(a)
                or a.is_relative_to("/proc")
                or a.is_relative_to("/dev")
                or a in {Path("/pytest.ini"), Path("/forbidden")}
                for a in virtual
            )
        ):
            raise ValueError("fixed runtime/project mounts overlap reserved confinement paths")

    def as_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "project_root": str(self.project_root),
            "selectors": list(self.selectors),
            "runtime_root": str(self.runtime.root),
            "runtime_digest": self.runtime.digest,
            "interpreter": str(self.runtime.interpreter),
            "interpreter_digest": self.runtime.interpreter_digest,
            "stdlib_virtual": self.runtime.stdlib_virtual,
            "pytest_version": self.runtime.pytest_version,
            "tool_runtime": self.tool_runtime,
            "tool_name": self.tool_name,
        }


@dataclass(frozen=True)
class _Snapshot:
    reference: str
    route: TestRoute
    root: Path
    tree: str
    source_identity: str
    target: str


class LinuxConfinedTestRunner:
    """Closed pytest effect route; results are untrusted diagnostics, not approval."""

    name = "linux-confined-test-v1"

    def __init__(
        self,
        routes: tuple[TestRoute, ...],
        install_root: Path,
        *,
        operator: object,
        limits: ProtectedProcessLimits = ProtectedProcessLimits(
            timeout_ms=30000, cpu_seconds=10, memory_mib=512
        ),
        maximum_jobs: int = 16,
    ):
        if type(operator) is not object or type(routes) is not tuple or not 1 <= len(routes) <= 16:
            raise ValueError("original operator and finite fixed test catalogue required")
        if any(type(route) is not TestRoute for route in routes) or len(
            {route.test_id for route in routes}
        ) != len(routes):
            raise ValueError("distinct exact fixed test routes required")
        self._operator, self.routes, self.root, self.limits = (
            operator,
            routes,
            Path(install_root).absolute(),
            limits,
        )
        self._limit, self._nonce, self._lock = maximum_jobs, uuid4().hex, RLock()
        self._snapshots: dict[str, _Snapshot] = {}
        self._plans: dict[str, tuple[EnforcementPlan, _Snapshot]] = {}
        self._jobs: dict[ProtectedProcessJob, EnforcementPlan] = {}
        self._outcomes: dict[ExecutorOutcome, tuple[EnforcementPlan, str, dict]] = {}
        if any(
            left == right or left.is_relative_to(right)
            for route in routes
            for left, right in (
                (self.root, route.project_root),
                (route.project_root, self.root),
                (self.root, route.runtime.root),
                (route.runtime.root, self.root),
            )
        ):
            raise ValueError("test installation, project and runtime roots must not overlap")
        self._engine = LinuxProtectedProcess(
            self.root, operator=operator, limits=limits, maximum_jobs=maximum_jobs
        )

    @property
    def configuration_digest(self) -> str:
        return digest(
            [
                self._nonce,
                [route.as_dict() for route in self.routes],
                self._engine.configuration_digest,
            ]
        )

    def _check(self, operator) -> None:
        if operator is not self._operator:
            raise ValueError("original fixed-test operator required")

    def _route(self, action: ActionEnvelope) -> TestRoute:
        if (
            type(action) is not ActionEnvelope
            or action.kind != "tool"
            or action.operation != "call"
        ):
            raise ValueError("fixed test tool action required")
        args = action.parameters.get("arguments")
        if not isinstance(args, Mapping):
            raise ValueError("fixed test_id argument required")
        if set(args) != {"test_id"} or type(args["test_id"]) is not str:
            raise ValueError("only fixed test_id is accepted")
        route = next((r for r in self.routes if r.test_id == args["test_id"]), None)
        if route is None or (action.parameters.get("runtime"), action.parameters.get("tool")) != (
            route.tool_runtime,
            route.tool_name,
        ):
            raise ValueError("fixed test catalogue entry not available")
        return route

    @staticmethod
    def _target(action) -> str:
        material = action.as_dict()
        material.pop("action_id")
        material["parameters"].pop("host_test_snapshot", None)
        return digest(material)

    def _verify_runtime(self, route: TestRoute) -> None:
        if (
            load_python_runtime_catalog(route.runtime.root, operator=self._operator)
            != route.runtime
        ):
            raise ValueError("original pinned runtime catalogue differs")

    def prepare_action(self, action: ActionEnvelope, *, operator: object) -> ActionEnvelope:
        self._check(operator)
        route = self._route(action)
        with self._lock:
            if "host_test_snapshot" in action.parameters:
                self._snapshot(action)
                return action
            if not self._engine.candidate:
                raise ValueError("qualified protected test process unavailable")
            if len(self._snapshots) >= self._limit:
                raise ValueError("fixed test snapshot history capacity reached")
            self._verify_runtime(route)
            before, contents = _capture(route.project_root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
            for selector in route.selectors:
                if selector.split("::")[0] not in contents:
                    raise ValueError("selected test file is absent from pinned project")
            reference = uuid4().hex
            snapshot_root = self.root / ("snapshot-" + reference)
            try:
                _copy_capture(snapshot_root, before, contents)
                after, _ = _capture(route.project_root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
                copied, _ = _capture(snapshot_root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
                tree = _tree_digest(before)
                if before != after or _tree_digest(copied) != tree:
                    raise ValueError("project changed or snapshot capture was ambiguous")
            except BaseException:
                if snapshot_root.parent != self.root or snapshot_root.is_symlink():
                    raise ValueError("owned snapshot cleanup target differs") from None
                if snapshot_root.exists():
                    shutil.rmtree(snapshot_root)
                raise
            row = _Snapshot(
                reference,
                route,
                snapshot_root,
                tree,
                hashlib.sha256(_wire(before)).hexdigest(),
                self._target(action),
            )
            self._snapshots[reference] = row
            return replace(
                action,
                parameters={
                    **action.parameters,
                    "host_test_snapshot": {"reference": reference, "digest": tree},
                },
            )

    def _snapshot(self, action) -> _Snapshot:
        value = action.parameters.get("host_test_snapshot")
        if (
            not isinstance(value, Mapping)
            or set(value) != {"reference", "digest"}
            or any(type(value[key]) is not str for key in ("reference", "digest"))
        ):
            raise ValueError("original retained test snapshot required")
        row = self._snapshots.get(value["reference"])
        if (
            row is None
            or row.route is not self._route(action)
            or (row.tree != value["digest"] or row.target != self._target(action))
        ):
            raise ValueError("test snapshot scope or original custody changed")
        before, _ = _capture(row.route.project_root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
        copied, _ = _capture(row.root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
        if (
            hashlib.sha256(_wire(before)).hexdigest() != row.source_identity
            or _tree_digest(copied) != row.tree
        ):
            raise ValueError("project or original sealed snapshot changed")
        self._verify_runtime(row.route)
        return row

    def validate_action_requirements(
        self, action: ActionEnvelope, contract: RuntimeCapabilityContract
    ) -> bool:
        try:
            row = self._snapshot(action)
            return (
                type(contract) is RuntimeCapabilityContract
                and not contract.unknowns
                and contract.action_digest == digest(action.as_dict())
                and not contract.network
                and not contract.credentials
                and contract.process.execution is True
                and contract.process.executables == (str(row.route.runtime.interpreter),)
                and contract.process.spawn_children is False
                and contract.privilege.escalation is False
                and contract.privilege.required_euid in {None, 65534}
                and contract.filesystem
                == tuple(
                    sorted(
                        (
                            FilesystemCapability("read", str(row.route.project_root), "prefix"),
                            FilesystemCapability("read", str(row.route.runtime.root), "prefix"),
                        ),
                        key=lambda value: (value.access, value.path or "", value.scope),
                    )
                )
                and len(contract.tools) == 1
                and (
                    contract.tools[0].runtime,
                    contract.tools[0].server,
                    contract.tools[0].tool,
                    contract.tools[0].operation,
                )
                == (row.route.tool_runtime, None, row.route.tool_name, "call")
            )
        except (OSError, ValueError, TypeError, KeyError):
            return False

    def compile_action(
        self, action: ActionEnvelope, contract: RuntimeCapabilityContract
    ) -> CompilationResult:
        if not self._engine.candidate:
            return CompilationResult(
                "unsupported",
                self.name,
                "tests.qualified_linux_required",
                unsupported_fields=("runtime.protected_test_process",),
            )
        if (
            not self.validate_action_requirements(action, contract)
            or contract.grant_state == "diagnostic"
        ):
            return CompilationResult(
                "unsupported",
                self.name,
                "tests.exact_scope_required",
                unsupported_fields=("tests.fixed_snapshot_and_complete_contract",),
            )
        row = self._snapshot(action)
        plan = EnforcementPlan(
            self.name,
            contract,
            {
                "configuration_digest": self.configuration_digest,
                "test_id": row.route.test_id,
                "snapshot_reference": row.reference,
                "snapshot_digest": row.tree,
                "interpreter_digest": row.route.runtime.interpreter_digest,
                "runtime_digest": row.route.runtime.digest,
            },
        )
        with self._lock:
            previous = self._plans.get(plan.plan_id)
            if previous is not None:
                plan = previous[0]
            else:
                if len(self._plans) >= self._limit * 4:
                    raise ValueError("fixed test plan history capacity reached")
                self._plans[plan.plan_id] = (plan, row)
        return CompilationResult("success", self.name, "tests.fixed_process_compiled", plan=plan)

    def validate(self, plan: EnforcementPlan) -> BackendValidationResult:
        if type(plan) is not EnforcementPlan:
            raise ValueError("exact fixed test plan required")
        original = self._plans.get(plan.plan_id) if type(plan) is EnforcementPlan else None
        valid = (
            original is not None
            and original[0] is plan
            and (plan.policy["configuration_digest"] == self.configuration_digest)
        )
        if valid and original is not None:
            try:
                row = original[1]
                copied, _ = _capture(row.root, MAX_PROJECT_FILES, MAX_PROJECT_BYTES)
                valid = _tree_digest(copied) == row.tree
                self._verify_runtime(row.route)
            except (OSError, ValueError):
                valid = False
        return BackendValidationResult(
            "success" if valid else "invalid",
            self.name,
            plan.policy_digest,
            "tests.original_plan_valid" if valid else "tests.original_plan_changed",
        )

    def create_job(self, plan: EnforcementPlan, *, operator: object) -> ProtectedProcessJob:
        self._check(operator)
        if not self.validate(plan).ok:
            raise ValueError("original fixed test plan required")
        row = self._plans[plan.plan_id][1]
        settings = {
            "project_root": str(row.route.project_root),
            "snapshot": str(row.root),
            "snapshot_digest": row.tree,
            "runtime_root": str(row.route.runtime.root),
            "runtime_digest": row.route.runtime.digest,
            "stdlib_virtual": row.route.runtime.stdlib_virtual,
            "selectors": list(row.route.selectors),
        }
        job = self._engine._prepare_test(
            settings, digest([plan.plan_id, row.tree]), operator=operator
        )
        self._jobs[job] = plan
        return job

    def execute(
        self,
        plan: EnforcementPlan,
        action: ActionEnvelope,
        source: RuntimeEvidenceSource,
        *,
        operator: object,
        job: ProtectedProcessJob | None = None,
    ) -> ExecutorOutcome:
        self._check(operator)
        if (
            type(source) is not RuntimeEvidenceSource
            or not self.validate(plan).ok
            or (
                plan.contract.grant_state != "eligible"
                or digest(action.as_dict()) != plan.contract.action_digest
            )
        ):
            raise ValueError("original eligible exact test plan/action/reporting source required")
        self._snapshot(action)
        job = self.create_job(plan, operator=operator) if job is None else job
        if self._jobs.get(job) is not plan:
            raise ValueError("test job belongs to another original plan")
        if self._engine.start(job, operator=operator):
            self._engine.admit(job, operator=operator)
        native = self._engine.finish(job, operator=operator)
        evidence = self._engine.evidence_record(native)
        diagnostic = native.output[:8192]
        value = _wire(
            {
                "exit_code": native.exit_code,
                "output": diagnostic.decode("utf-8", "replace"),
                "output_truncated": len(diagnostic) != native.output_bytes,
                "output_trust": "untrusted_test_diagnostic",
                "test_correctness_verified": False,
                "snapshot_digest": self._plans[plan.plan_id][1].tree,
            }
        )
        physical = native.isolation_digest is not None
        completed = native.status == "exited"
        status = (
            "completed"
            if completed
            else native.status
            if native.status in {"unsupported", "canceled", "unknown"}
            else "unknown"
        )
        observation = (
            source.observe(
                plan.contract,
                observation_id="confined-test-" + uuid4().hex,
                trust="backend_observed",
                enforcement_point="process",
                outcome="completed",
                operation="process.execute",
                effects=("code.execute",),
                resources=(
                    ObservedResource(
                        "executable", str(self._plans[plan.plan_id][1].route.runtime.interpreter)
                    ),
                ),
                reason_code="tests.original_confined_process_exited",
                metadata={"event_digest": digest(evidence), "test_correctness_verified": False},
            )
            if completed
            else None
        )
        result = ExecutorOutcome(
            status,
            "tests.original_confined_process_" + status,
            plan.contract.action_digest,
            plan.contract.digest,
            plan.policy_digest,
            physical,
            digest(evidence),
            native.output_bytes,
            len(value),
            hashlib.sha256(value).hexdigest(),
            value,
            observation,
            backend=self.name,
        )
        self._outcomes[result] = (plan, digest(result.as_dict()), evidence)
        return result

    def request_stop(self, job, *, operator):
        return self._engine.request_stop(job, operator=operator)

    def job_status(self, job, *, operator):
        return self._engine.status(job, operator=operator)

    def verify_outcome(self, outcome, plan) -> bool:
        row = self._outcomes.get(outcome) if type(outcome) is ExecutorOutcome else None
        return row is not None and row[0] is plan and row[1] == digest(outcome.as_dict())

    def evidence_record(self, outcome) -> dict:
        row = self._outcomes.get(outcome)
        if row is None or not self.verify_outcome(outcome, row[0]):
            raise ValueError("original fixed test outcome required")
        return json.loads(json.dumps(row[2]))

    def close(self, *, operator):
        self._check(operator)
        self._engine.close(operator=operator)

    def factory_probe(self, root: Path, *, operator: object, policy_digest: str):
        """Explicit installation self-test; configured project code is never used.

        The temporary fixture is trusted constant source. This special operator
        probe cannot approve any workload or turn its diagnostics into authority.
        Original receipt membership remains verifiable after closing the probe.
        """
        self._check(operator)
        _hex(policy_digest)
        _private_directory(root, empty=True)
        workspace, install = root / "fixture", root / "install"
        workspace.mkdir(mode=0o700)
        install.mkdir(mode=0o700)
        (workspace / "test_probe.py").write_text(
            "def test_fixed_installation_fixture():\n    assert 2 + 2 == 4\n", encoding="utf-8"
        )
        route = TestRoute(
            "installation-probe", workspace, ("test_probe.py",), self.routes[0].runtime
        )
        probe = LinuxConfinedTestRunner((route,), install, operator=operator, limits=self.limits)
        try:
            action = probe.prepare_action(
                ToolCallAdapter(route.tool_runtime).adapt(
                    route.tool_name,
                    {"test_id": route.test_id},
                    action_id="factory-" + uuid4().hex,
                ),
                operator=operator,
            )
            contract = RuntimeCapabilityContract(
                action.action_id,
                digest(action.as_dict()),
                "allow",
                "low",
                filesystem=tuple(
                    sorted(
                        (
                            FilesystemCapability("read", str(workspace), "prefix"),
                            FilesystemCapability("read", str(route.runtime.root), "prefix"),
                        ),
                        key=lambda value: value.path or "",
                    )
                ),
                tools=(ToolCapability(route.tool_runtime, None, route.tool_name),),
                process=ProcessCapability(True, (str(route.runtime.interpreter),), False),
                privilege=PrivilegeCapability(False),
                source={
                    "kind": "tool",
                    "adapter": "confined_test_factory_probe",
                    "operation": "call",
                    "effects": ["code.execute"],
                    "provenance_digest": None,
                },
            )
            compiled = probe.compile_action(action, contract)
            if not compiled.enforceable or compiled.plan is None:
                raise ValueError("fixed test installation probe cannot compile")
            source = RuntimeEvidenceSource(
                probe.name,
                digest([self._nonce, policy_digest]),
                "factory-" + uuid4().hex,
                compiled.plan.policy_digest,
            )
            outcome = probe.execute(compiled.plan, action, source, operator=operator)
            if (
                outcome.status != "completed"
                or not outcome.physical_enforcement
                or not (probe.verify_outcome(outcome, compiled.plan))
                or outcome.value is None
                or json.loads(outcome.value)["exit_code"] != 0
            ):
                raise ValueError("fixed test installation kernel/fixture probe did not complete")
            evidence = probe.evidence_record(outcome)
            description = {
                "scope": "fresh_fixed_test_fixture_only",
                "factory": True,
                "requires_action_admission": True,
                "requires_warning_approval": True,
                "supported_action_kinds": ["tool"],
                "operations": ["call"],
                "effects": ["code.execute"],
                "test_ids": [r.test_id for r in self.routes],
                "limits": self.limits.as_dict(),
                "evidence_digest": digest(evidence),
                "test_correctness_verified": False,
                "execution_authority": False,
            }
            return probe, outcome, compiled.plan, evidence, description
        except BaseException:
            probe.close(operator=operator)
            raise
