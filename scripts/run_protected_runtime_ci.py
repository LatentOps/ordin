"""Stage a private CI base interpreter; never relax the production collector."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_FILES = 30000
MAX_EVIDENCE = 16 * 1024 * 1024
EXCLUDED_DIRS = {"site-packages", "dist-packages", "__pycache__"}
EXCLUDED_FILES = {"sitecustomize.py", "usercustomize.py"}
IMPORT_ARCHIVE = r"python[0-9]+\.zip"
EXPORTS = {
    "preflight.json": "preflight.json",
    "driver-provenance.json": "driver-provenance.json",
    "collector/evidence/junit.xml": "junit.xml",
    "collector/evidence/protected-runtime.json": "protected-runtime.json",
}

PROBE = r"""
import json,sys,sysconfig,ctypes,ssl,zlib,math,_socket,_hashlib
from pathlib import Path
maps=Path('/proc/self/maps')
print(json.dumps({
 'version':list(sys.version_info), 'abiflags':sys.abiflags,
 'soabi':sysconfig.get_config_var('SOABI'),
 'executable':str(Path(sys.executable).resolve()),
 'base_executable':str(Path(getattr(sys,'_base_executable',sys.executable)).resolve()),
 'prefix':str(Path(sys.prefix).resolve()), 'base_prefix':str(Path(sys.base_prefix).resolve()),
 'stdlib':str(Path(sysconfig.get_path('stdlib')).resolve()),
 'sysconfig':str(Path(sysconfig.__file__).resolve()), 'sys_path':sys.path,
 'ldversion':sysconfig.get_config_var('LDVERSION'),
 'ldlibrary':sysconfig.get_config_var('LDLIBRARY'), 'libpl':sysconfig.get_config_var('LIBPL'),
 'python_maps':sorted({line.split()[-1] for line in maps.read_text().splitlines()
                      if '/' in line and ('libpython' in line or '/hostedtoolcache/' in line
                         or '/python%d.%d/' % sys.version_info[:2] in line)})
               if maps.exists() else []
},sort_keys=True))
"""


def _identity(info) -> tuple:
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


def _lstat(path: Path):
    return path.lstat()


def _resolve(path: Path, *, strict=True) -> Path:
    return path.resolve(strict=strict)


def _canonical(path: Path) -> Path:
    if not path.is_absolute() or _resolve(path) != path:
        raise ValueError("canonical absolute existing path required")
    return path


def _posix_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value <= 0:
        raise ValueError("required Linux descriptor flag is unavailable")
    return value


def _set_export_metadata(descriptor: int, uid: int, gid: int, mode: int) -> None:
    chown, chmod = getattr(os, "fchown", None), getattr(os, "fchmod", None)
    if not callable(chown) or not callable(chmod):
        raise ValueError("required Linux descriptor ownership controls are unavailable")
    chown(descriptor, uid, gid)
    chmod(descriptor, mode)


def trusted_directory(path: Path, *, owner=0) -> None:
    _canonical(path)
    for selected in (path, *path.parents):
        info = _lstat(selected)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ValueError("private CI ancestor is not trusted")


def read_regular(path: Path, *, maximum=MAX_FILE, owner=None) -> tuple[bytes, os.stat_result]:
    before = _lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
        or owner is not None
        and before.st_uid != owner
    ):
        raise ValueError("bounded original regular file required")
    fd = os.open(path, os.O_RDONLY | _posix_flag("O_NOFOLLOW"))
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise ValueError("source changed before capture")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(maximum + 1)
        if (
            len(data) > maximum
            or _identity(os.fstat(fd)) != _identity(before)
            or _identity(_lstat(path)) != _identity(before)
        ):
            raise ValueError("source changed during capture")
        return data, before
    finally:
        os.close(fd)


def _write(path: Path, data: bytes, mode=0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _posix_flag("O_NOFOLLOW"), mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    path.chmod(mode)


def _json(path: Path, value) -> None:
    _write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def validate_selected(value: dict, minor: str) -> Path:
    version = value.get("version")
    if (
        not re.fullmatch(r"3\.(?:10|13)", minor)
        or not isinstance(version, list)
        or len(version) != 5
        or any(type(item) is not int or item < 0 for item in version[:3])
        or version[:2] != list(map(int, minor.split(".")))
        or version[3:] != ["final", 0]
    ):
        raise ValueError("selected exact Python version does not match matrix")
    base = _canonical(Path(value["base_prefix"]))
    if (
        base == Path(base.anchor)
        or value.get("prefix") != str(base)
        or (base / "pyvenv.cfg").exists()
    ):
        raise ValueError("selected installation must be a base, never an existing venv")
    for key in ("executable", "base_executable", "stdlib", "sysconfig"):
        selected = _canonical(Path(value[key]))
        if not selected.is_relative_to(base):
            raise ValueError("selected runtime path escapes base installation")
    if value["executable"] != value["base_executable"] or not isinstance(value.get("soabi"), str):
        raise ValueError("selected executable or ABI identity is ambiguous")
    return base


def _rebase_sysconfig(
    relative: Path, data: bytes, original: Path, staged: Path, compiled_prefix=None
):
    if relative.name.startswith("_sysconfigdata") and relative.suffix == ".py":
        tree = ast.parse(data)
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "build_time_vars"
        ]
        if len(assignments) != 1 or any(
            node is not assignments[0]
            and not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            )
            for node in tree.body
        ):
            raise ValueError("unsupported sysconfig data layout")
        values = ast.literal_eval(assignments[0].value)
        if not isinstance(values, dict):
            raise ValueError("sysconfig build variables must be literal data")
        prefixes = {str(original), original.as_posix()}
        if compiled_prefix is not None:
            prefixes.update({str(compiled_prefix), compiled_prefix.as_posix()})

        def relocated(value):
            if isinstance(value, str):
                for prefix in sorted(prefixes, key=len, reverse=True):
                    value = value.replace(prefix, str(staged))
            return value

        transforms = [
            {"key": key, "from": value, "to": relocated(value)}
            for key, value in values.items()
            if relocated(value) != value
        ]
        values = {key: relocated(value) for key, value in values.items()}
        return (
            "# CI relocation of literal build paths only.\nbuild_time_vars = " + repr(values) + "\n"
        ).encode(), transforms
    return data, []


def read_runtime_file(original: Path, entry: Path, depth=0):
    """Open each parent without following links, then capture one original file."""
    if depth > 16 or not entry.is_relative_to(original):
        raise ValueError("runtime alias escapes base or exceeds link bound")
    parent = _open_directory(entry.parent)
    try:
        before = os.stat(entry.name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raw = Path(os.readlink(entry.name, dir_fd=parent))
            relative = (
                raw.relative_to(original)
                if raw.is_absolute()
                else entry.parent.relative_to(original) / raw
            )
            parts: list[str] = []
            for index, part in enumerate(relative.parts):
                if part == "..":
                    if not parts:
                        raise ValueError("runtime source alias escapes selected base")
                    parts.pop()
                elif part != ".":
                    parts.append(part)
                    if index < len(relative.parts) - 1:
                        info = _lstat(original.joinpath(*parts))
                        if not stat.S_ISDIR(info.st_mode):
                            raise ValueError("runtime directory aliases are not accepted")
            selected = original.joinpath(*parts)
            data, captured, selected = read_runtime_file(original, selected, depth + 1)
        else:
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > MAX_FILE
            ):
                raise ValueError("runtime source must be a bounded regular file without hardlinks")
            fd = os.open(entry.name, os.O_RDONLY | _posix_flag("O_NOFOLLOW"), dir_fd=parent)
            try:
                if _identity(os.fstat(fd)) != _identity(before):
                    raise ValueError("runtime source changed before read")
                with os.fdopen(fd, "rb", closefd=False) as handle:
                    data = handle.read(MAX_FILE + 1)
                if len(data) > MAX_FILE or _identity(os.fstat(fd)) != _identity(before):
                    raise ValueError("runtime source changed during read")
            finally:
                os.close(fd)
            captured, selected = before, entry
        if _identity(os.stat(entry.name, dir_fd=parent, follow_symlinks=False)) != _identity(
            before
        ):
            raise ValueError("runtime alias changed during read")
        return data, captured, selected
    finally:
        os.close(parent)


def copy_base(original: Path, staged: Path, *, compiled_prefix=None) -> list[dict]:
    """Copy only into a new directory; never chmod/chown the selected cache."""
    _canonical(original)
    if (original / "pyvenv.cfg").exists() or staged.exists() or staged.is_symlink():
        raise ValueError("base source and fresh stage required")
    staged.mkdir(mode=0o700)
    records: list[dict] = []
    seen: set[tuple[int, int]] = set()
    total = 0

    def visit(source: Path, destination: Path):
        nonlocal total
        before = _lstat(source)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("runtime directory aliases are not accepted")
        for entry in sorted(source.iterdir()):
            if (
                entry.name in EXCLUDED_DIRS
                or entry.name in EXCLUDED_FILES
                or entry.suffix in {".pth", ".pyc", ".pyo"}
                or re.fullmatch(IMPORT_ARCHIVE, entry.name) is not None
            ):
                continue
            info = _lstat(entry)
            target = destination / entry.name
            if stat.S_ISDIR(info.st_mode):
                target.mkdir(mode=0o700)
                visit(entry, target)
                continue
            selected = _resolve(entry)
            if not selected.is_relative_to(original):
                raise ValueError("runtime source alias escapes selected base")
            if stat.S_ISLNK(info.st_mode) and selected.is_dir():
                raise ValueError("runtime directory aliases are not accepted")
            data, captured, selected = read_runtime_file(original, entry)
            identity = (captured.st_dev, captured.st_ino)
            if not stat.S_ISLNK(info.st_mode):
                if identity in seen:
                    raise ValueError("runtime hardlink alias is not accepted")
                seen.add(identity)
            relative = entry.relative_to(original)
            rebased, transforms = _rebase_sysconfig(
                relative, data, original, staged, compiled_prefix
            )
            elf_transforms = []
            if rebased.startswith(b"\x7fELF") and (
                relative.parts[0] == "bin" or ".so" in relative.name
            ):
                rebased, elf_transforms = relocate_runpaths(
                    relative, rebased, original, staged, compiled_prefix
                )
            total += len(rebased)
            if len(records) >= MAX_FILES or total > MAX_TOTAL:
                raise ValueError("runtime copy exceeds fixed bounds")
            mode = 0o555 if captured.st_mode & 0o111 else 0o444
            _write(target, rebased, mode)
            if _identity(_lstat(entry)) != _identity(info):
                raise ValueError("runtime source alias changed during capture")
            records.append(
                {
                    "kind": "file",
                    "path": relative.as_posix(),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "staged_sha256": hashlib.sha256(rebased).hexdigest(),
                    "source_uid": captured.st_uid,
                    "source_gid": captured.st_gid,
                    "source_mode": stat.S_IMODE(captured.st_mode),
                    "source_alias": str(selected.relative_to(original))
                    if entry.is_symlink()
                    else None,
                    "staged_uid": target.stat().st_uid,
                    "staged_mode": mode,
                    "literal_sysconfig_transforms": transforms,
                    "elf_runpath_transforms": elf_transforms,
                }
            )
        if _identity(_lstat(source)) != _identity(before):
            raise ValueError("runtime directory changed during capture")
        destination.chmod(0o700 if destination == staged else 0o755)
        if len(records) >= MAX_FILES:
            raise ValueError("runtime copy exceeds fixed path bound")
        records.append(
            {
                "kind": "directory",
                "path": source.relative_to(original).as_posix(),
                "source_uid": before.st_uid,
                "source_gid": before.st_gid,
                "source_mode": stat.S_IMODE(before.st_mode),
                "staged_uid": destination.stat().st_uid,
                "staged_mode": 0o700 if destination == staged else 0o755,
            }
        )

    visit(original, staged)
    return records


def validate_staged(selected: dict, observed: dict, staged: Path) -> None:
    for key in ("version", "abiflags", "soabi", "ldversion", "ldlibrary"):
        if observed.get(key) != selected.get(key):
            raise ValueError("staged version or ABI differs from selected installation")
    old = Path(selected["base_prefix"])
    for key in ("executable", "base_executable", "stdlib", "sysconfig", "prefix", "base_prefix"):
        expected = staged / Path(selected[key]).relative_to(old)
        if observed.get(key) != str(expected) or not Path(observed[key]).resolve().is_relative_to(
            staged
        ):
            raise ValueError("staged interpreter did not relocate into private base")
    if any(
        str(old) in path or "/hostedtoolcache/" in path
        for path in observed.get("sys_path", []) + observed.get("python_maps", [])
    ):
        raise ValueError("staged interpreter still uses the original tool cache")
    if not observed.get("sys_path") or any(
        not Path(path).is_absolute() or not Path(path).is_relative_to(staged)
        for path in observed["sys_path"]
    ):
        raise ValueError("staged interpreter search path is outside private base")
    if any(not Path(path).is_relative_to(staged) for path in observed.get("python_maps", [])):
        raise ValueError("mapped Python library is outside private base")
    stdlib = Path(observed["stdlib"])
    version, library, libpl = (observed.get(key) for key in ("ldversion", "ldlibrary", "libpl"))
    if (
        not isinstance(version, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+[a-z]*", version) is None
        or library != "libpython" + version + ".so"
        or not isinstance(libpl, str)
        or Path(libpl).parent != stdlib
        or re.fullmatch(
            r"config-" + re.escape(version) + r"(?:-[A-Za-z0-9_.-]{1,128})?", Path(libpl).name
        )
        is None
        or Path(libpl).resolve(strict=True) != Path(libpl)
    ):
        raise ValueError("relocated LIBPL does not meet the existing exact linker curation")


def elf_routes(data: bytes, *, with_slots=False) -> dict:
    """Read ELF64 program/dynamic tables as data; never invoke an ELF or ldd."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("qualified runtime requires ELF64 little-endian metadata")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[1] not in {2, 3} or header[2] != 62 or header[9] != 56 or not 0 < header[10] <= 1024:
        raise ValueError("unsupported runtime ELF header")
    offset, count = header[5], header[10]
    if offset + count * 56 > len(data):
        raise ValueError("runtime ELF program table is truncated")
    loads, dynamics, interpreters = [], [], []
    for index in range(count):
        kind, _, start, address, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * 56
        )
        if start + size > len(data):
            raise ValueError("runtime ELF segment is truncated")
        if kind == 1:
            loads.append((address, size, start))
        elif kind == 2:
            dynamics.append((start, size))
        elif kind == 3:
            raw = data[start : start + size]
            if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                raise ValueError("invalid runtime ELF interpreter")
            interpreters.append(raw[:-1].decode("utf-8"))
    if len(dynamics) > 1 or len(interpreters) > 1:
        raise ValueError("ambiguous runtime ELF loader metadata")
    result: dict = {
        "interpreter": interpreters[0] if interpreters else None,
        "needed": [],
        "search": [],
    }
    if with_slots:
        result.update(slots=[], identity_strings=[])
    if not dynamics:
        return result
    start, size = dynamics[0]
    if size % 16 or size > 1024 * 1024:
        raise ValueError("invalid runtime ELF dynamic table")
    entries = []
    for index in range(0, size, 16):
        tag, value = struct.unpack_from("<qQ", data, start + index)
        if tag == 0:
            break
        if tag in {0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFF, 0x7FFFFFFD}:
            raise ValueError("runtime ELF audit/filter plugins are not accepted")
        entries.append((tag, value))
    else:
        raise ValueError("unterminated runtime ELF dynamic table")
    tables = [value for tag, value in entries if tag == 5]
    sizes = [value for tag, value in entries if tag == 10]
    if len(tables) != 1 or len(sizes) != 1 or sizes[0] > MAX_FILE:
        raise ValueError("ambiguous runtime ELF string table")
    locations = [
        position + tables[0] - address
        for address, length, position in loads
        if address <= tables[0] and tables[0] + sizes[0] <= address + length
    ]
    if len(locations) != 1:
        raise ValueError("runtime ELF strings escape file-backed load segments")
    strings = data[locations[0] : locations[0] + sizes[0]]

    def text(position):
        if position >= len(strings):
            raise ValueError("runtime ELF string is out of bounds")
        end = strings.find(b"\0", position)
        if end < 0 or end - position > 4096:
            raise ValueError("runtime ELF string is unbounded")
        return strings[position:end].decode("utf-8")

    result["needed"] = [text(value) for tag, value in entries if tag == 1]
    # ld.so uses RUNPATH instead of RPATH when both are present.
    active = 29 if any(tag == 29 for tag, _ in entries) else 15
    result["search"] = [
        part for tag, value in entries if tag == active for part in text(value).split(":")
    ]
    if with_slots:
        result["slots"] = [
            {"offset": locations[0] + value, "text": text(value), "tag": tag}
            for tag, value in entries
            if tag in {15, 29}
        ]
        identities = [(tag, text(value)) for tag, value in entries if tag in {1, 14}]
        if any(tag == 6 for tag, _ in entries):  # DT_SYMTAB: preserve every dynamic symbol name.
            section_offset, section_size, section_count = header[6], header[11], header[12]
            if (
                section_size != 64
                or not 0 < section_count <= 4096
                or section_offset + section_size * section_count > len(data)
            ):
                raise ValueError("ELF symbol identities cannot be established")
            sections = [
                struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * 64)
                for index in range(section_count)
            ]
            symbols = [section for section in sections if section[1] == 11]
            if not symbols:
                raise ValueError("ELF symbol identities cannot be established")
            for section in symbols:
                if (
                    section[9] != 24
                    or section[5] % 24
                    or section[4] + section[5] > len(data)
                    or section[6] >= len(sections)
                    or sections[section[6]][4] != locations[0]
                ):
                    raise ValueError("ELF dynamic symbol table is ambiguous")
                for offset in range(section[4], section[4] + section[5], 24):
                    identities.append((6, text(struct.unpack_from("<I", data, offset)[0])))
        result["identity_strings"] = identities
    return result


def relocate_runpaths(
    relative: Path, data: bytes, original: Path, staged: Path, compiled_prefix=None
):
    """Replace only measured exact prefix/lib strings in their existing ELF slots."""
    before = elf_routes(data, with_slots=True)
    allowed = {str(original / "lib"), (original / "lib").as_posix()}
    if compiled_prefix is not None:
        allowed.update({str(compiled_prefix / "lib"), (compiled_prefix / "lib").as_posix()})
    library = staged / "lib"
    origin = (staged / relative).parent
    route = os.path.relpath(library, origin).replace("\\", "/")
    replacement = "$ORIGIN" if route == "." else "$ORIGIN/" + route
    if not _resolve(origin / route, strict=False).is_relative_to(staged):
        raise ValueError("ELF relocation target escapes new base")
    changed, transforms = bytearray(data), []
    for slot in before.get("slots", []):
        old = slot["text"]
        if old not in allowed:
            continue  # The unchanged strict loader audit decides every unknown route.
        encoded, previous = replacement.encode("utf-8"), old.encode("utf-8")
        if len(encoded) > len(previous):
            raise ValueError("contained ELF relocation does not fit original string slot")
        start = slot["offset"]
        if data[start : start + len(previous) + 1] != previous + b"\0":
            raise ValueError("ELF route slot differs from inspected original")
        changed[start : start + len(previous) + 1] = encoded + b"\0" * (
            len(previous) + 1 - len(encoded)
        )
        transforms.append(
            {
                "offset": start,
                "tag": slot["tag"],
                "from": old,
                "to": replacement,
                "slot_bytes": len(previous) + 1,
            }
        )
    result = bytes(changed)
    after = elf_routes(result, with_slots=True)
    if len(result) != len(data) or any(
        after[key] != before[key] for key in ("interpreter", "needed", "identity_strings")
    ):
        raise ValueError("ELF relocation changed an unrelated loader identity")
    for index, (old_byte, new_byte) in enumerate(zip(data, result)):
        if old_byte != new_byte and not any(
            row["offset"] <= index < row["offset"] + row["slot_bytes"] for row in transforms
        ):
            raise ValueError("ELF relocation changed bytes outside inspected route slots")
    return result, transforms


def audit_loader_routes(staged: Path, python: Path, records: list[dict]) -> list[dict]:
    """Refuse writable-cache loader routes before the first root execution."""
    audited = []
    for row in records:
        if row["kind"] != "file":
            continue
        path = staged / row["path"]
        if path != python and ".so" not in path.name:
            continue
        data = read_regular(path, owner=0)[0]
        if not data.startswith(b"\x7fELF") and path != python:
            continue
        routes = elf_routes(data)

        def trusted_file(name):
            if not Path(name).is_absolute():
                raise ValueError("runtime ELF loader object path must be absolute")
            candidate = _resolve(Path(name))
            trusted_directory(candidate.parent)
            _, metadata = read_regular(candidate, owner=0)
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ValueError("runtime loader object is writable")

        if routes["interpreter"] is not None:
            trusted_file(routes["interpreter"])
        for name in routes["search"]:
            expanded = name.replace("${ORIGIN}", str(path.parent)).replace(
                "$ORIGIN", str(path.parent)
            )
            if not expanded or "$" in expanded or not Path(expanded).is_absolute():
                raise ValueError("runtime ELF loader search route is not qualified")
            trusted_directory(_resolve(Path(expanded)))
        for name in routes["needed"]:
            if "$" in name:
                raise ValueError("runtime ELF dependency token is not qualified")
            if "/" in name:
                if not Path(name).is_absolute():
                    raise ValueError("relative runtime ELF dependency is not qualified")
                trusted_file(name)
        audited.append({"path": row["path"], **routes})
    if not any(row["path"] == python.relative_to(staged).as_posix() for row in audited):
        raise ValueError("staged interpreter ELF identity was not inspected")
    return audited


def _open_directory(path: Path) -> int:
    """Descriptor walk prevents a mutable artifact ancestor redirecting root writes."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute artifact parent required")
    directory, nofollow = _posix_flag("O_DIRECTORY"), _posix_flag("O_NOFOLLOW")
    fd = os.open(path.anchor, os.O_RDONLY | directory)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | directory | nofollow, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def evidence_files(private: Path) -> dict[str, bytes]:
    result = {}
    for relative, name in EXPORTS.items():
        source = private / relative
        if not source.exists():
            if source.is_symlink():
                raise ValueError("artifact source alias is not accepted")
            continue
        if _resolve(source) != source or not source.is_relative_to(private):
            raise ValueError("artifact source escapes private workspace")
        result[name] = read_regular(source, maximum=MAX_EVIDENCE, owner=0)[0]
    return result


def export_evidence(private: Path, destination: Path, uid: int, gid: int) -> list[str]:
    if destination == private or destination.is_relative_to(private) or not destination.name:
        raise ValueError("artifact export must be separate and fresh")
    parent = _open_directory(destination.parent)
    directory = None
    exported = []
    try:
        if os.fstat(parent).st_uid != uid:
            raise ValueError("artifact parent must belong to the runner")
        os.mkdir(destination.name, 0o700, dir_fd=parent)
        directory = os.open(
            destination.name,
            os.O_RDONLY | _posix_flag("O_DIRECTORY") | _posix_flag("O_NOFOLLOW"),
            dir_fd=parent,
        )
        for name, data in evidence_files(private).items():
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _posix_flag("O_NOFOLLOW"),
                0o600,
                dir_fd=directory,
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                _set_export_metadata(handle.fileno(), uid, gid, 0o644)
                info = os.fstat(handle.fileno())
                if (
                    info.st_uid != uid
                    or info.st_gid != gid
                    or info.st_nlink != 1
                    or not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o644
                ):
                    raise ValueError("artifact file owner or mode differs")
            exported.append(name)
        _set_export_metadata(directory, uid, gid, 0o755)
        if os.fstat(directory).st_uid != uid or stat.S_IMODE(os.fstat(directory).st_mode) != 0o755:
            raise ValueError("artifact export owner or mode differs")
        if _identity(os.stat(destination.name, dir_fd=parent, follow_symlinks=False)) != _identity(
            os.fstat(directory)
        ):
            raise ValueError("artifact destination changed during export")
        return exported
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def run(command, *, env, cwd, capture=False):
    return subprocess.run(
        list(map(str, command)),
        env=env,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )


def _verify_bootstrap_identity(current: Path, expected: Path, info) -> None:
    if (
        current != expected
        or info.st_uid != 0
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("only trusted distro Python may bootstrap root staging")


def verify_bootstrap() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("trusted Linux root bootstrap required")
    bootstrap = Path("/usr/bin/python3").resolve(strict=True)
    trusted_directory(bootstrap.parent)
    bootstrap_info = bootstrap.stat()
    _verify_bootstrap_identity(Path(sys.executable).resolve(strict=True), bootstrap, bootstrap_info)


def drive(args) -> int:
    verify_bootstrap()
    source = _canonical(args.source)
    trusted_directory(args.private_root.parent)
    if (
        args.private_root.is_relative_to(source)
        or args.private_root.exists()
        or args.private_root.is_symlink()
    ):
        raise ValueError("new private task root outside checkout required")
    args.private_root.mkdir(mode=0o700)
    private = args.private_root
    status = 1
    provenance = {
        "revision": args.revision,
        "hosted_qualification": False,
        "status": "preflight",
        "approved_exports": EXPORTS,
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runtime_exclusion_policy": {
            "directories": sorted(EXCLUDED_DIRS),
            "files": sorted(EXCLUDED_FILES),
            "suffixes": [".pth", ".pyc", ".pyo"],
            "import_archive_pattern": IMPORT_ARCHIVE,
        },
    }
    try:
        provenance["phase"] = "selected_identity"
        raw, info = read_regular(args.identity, maximum=65536, owner=args.runner_uid)
        selected = json.loads(raw)
        original = validate_selected(selected, args.expected_minor)
        if original.is_relative_to(source) or private.is_relative_to(original):
            raise ValueError("runtime base and task source must be independent")
        original_info = original.stat()
        provenance["selected_base_metadata"] = {
            "uid": original_info.st_uid,
            "gid": original_info.st_gid,
            "mode": stat.S_IMODE(original_info.st_mode),
        }
        source_uid = source.stat().st_uid
        if source_uid not in {0, args.runner_uid}:
            raise ValueError("source checkout owner differs from explicit runner")
        clear = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(private),
            "TMPDIR": str(private / "tmp"),
            "SUDO_UID": str(source_uid),
            "ORDIN_REQUIRED_PROTECTED_PROCESS": "1",
            "ORDIN_REQUIRE_SWARM_BROKER": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
        (private / "tmp").mkdir(mode=0o700)
        provenance["phase"] = "exact_source"
        for command, expected in (
            (["/usr/bin/git", "rev-parse", "HEAD"], args.revision),
            (["/usr/bin/git", "status", "--porcelain"], ""),
        ):
            if run(command, env=clear, cwd=source, capture=True).stdout.strip() != expected:
                raise ValueError("exact clean source revision required")
        provenance.update(
            identity_sha256=hashlib.sha256(raw).hexdigest(),
            identity_uid=info.st_uid,
            selected=selected,
        )
        staged = private / "base"
        provenance["phase"] = "private_base_copy"
        version = ".".join(map(str, selected["version"][:3]))
        compiled_prefix = Path("/opt/hostedtoolcache/Python") / version / "x64"
        provenance["setup_python_compiled_prefix"] = compiled_prefix.as_posix()
        provenance["runtime_files"] = copy_base(original, staged, compiled_prefix=compiled_prefix)
        python = staged / Path(selected["base_executable"]).relative_to(original)
        provenance["phase"] = "loader_metadata"
        provenance["loader_routes"] = audit_loader_routes(
            staged, python, provenance["runtime_files"]
        )
        provenance["phase"] = "empty_environment_probe"
        observed = json.loads(
            run([python, "-I", "-S", "-B", "-c", PROBE], env={}, cwd=private, capture=True).stdout
        )
        validate_staged(selected, observed, staged)
        _json(
            private / "preflight.json",
            {"selected": selected, "staged": observed, "empty_environment_probe_passed": True},
        )
        collector = private / "collector-env"
        provenance["phase"] = "fresh_collector_environment"
        run([python, "-I", "-B", "-m", "venv", collector], env=clear, cwd=private)
        tool_python = collector / "bin/python"
        provenance["phase"] = "hash_locked_tools"
        run(
            [
                tool_python,
                "-I",
                "-B",
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                source / "requirements/dev-baseline.txt",
            ],
            env=clear,
            cwd=private,
        )
        provenance["phase"] = "unchanged_collector"
        result = subprocess.run(
            [
                str(tool_python),
                "-I",
                "-B",
                str(source / "scripts/check_protected_runtime.py"),
                "--revision",
                args.revision,
                "--workspace",
                str(private / "collector"),
            ],
            env=clear,
            cwd=source,
        )
        status = result.returncode
        provenance.update(status="collector_finished", collector_returncode=status)
    except Exception as error:
        provenance.update(status="failed", error_type=type(error).__name__)
        if isinstance(error, ValueError):
            provenance["failure_reason"] = str(error)[:512]
    finally:
        provenance["pre_export_status"] = status
        provenance["evidence_export"] = "not_yet_completed"
        if not (private / "preflight.json").exists():
            _json(
                private / "preflight.json",
                {"passed": False, "error_type": provenance.get("error_type")},
            )
        _json(private / "driver-provenance.json", provenance)
        try:
            export_evidence(private, args.export, args.runner_uid, args.runner_gid)
        except Exception:
            print("protected runtime approved evidence export failed", file=sys.stderr)
            status = status or 1
    return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-selected", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--expected-minor")
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--export", type=Path)
    parser.add_argument("--runner-uid", type=int)
    parser.add_argument("--runner-gid", type=int)
    args = parser.parse_args(argv)
    if args.capture_selected:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise ValueError("selected cache identity must be captured as the normal runner")
        exec(PROBE, {"__name__": "__main__"})
        return 0
    if (
        not args.source
        or not args.identity
        or not args.private_root
        or not args.export
        or not re.fullmatch(r"[a-f0-9]{40}", args.revision or "")
        or args.runner_uid is None
        or args.runner_uid <= 0
        or args.runner_gid is None
        or args.runner_gid < 0
    ):
        parser.error(
            "explicit source, identity, matrix, staging, revision and runner identity required"
        )
    return drive(args)


if __name__ == "__main__":
    raise SystemExit(main())
