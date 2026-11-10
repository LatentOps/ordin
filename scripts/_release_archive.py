"""Stdlib-only bounded release inputs, shared by historical and current verifiers."""

from __future__ import annotations

import gzip
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 8192


def read_file(path: Path, limit: int = MAX_ARCHIVE_BYTES) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("release input must be a bounded singly-linked regular file")
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if any(getattr(opened, key) != getattr(info, key) for key in fields):
            raise ValueError("release input changed before its bounded read")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    selected = path.lstat()
    if (
        len(raw) > limit
        or after.st_ctime_ns != opened.st_ctime_ns
        or selected.st_ctime_ns != info.st_ctime_ns
        or any(
            getattr(after, key) != getattr(info, key)
            or getattr(selected, key) != getattr(info, key)
            for key in fields
        )
    ):
        raise ValueError("release input changed or exceeded its bound")
    return raw


def read_json(path: Path, limit: int = MAX_MEMBER_BYTES):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate release JSON field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("nonfinite release JSON")

    try:
        result = json.loads(
            read_file(path, limit), object_pairs_hook=unique, parse_constant=invalid_constant
        )
        pending, count = [(result, 0)], 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if count > 65536 or depth > 16:
                raise ValueError("release JSON exceeds structural bounds")
            if type(value) is str:
                value.encode("utf-8")
            elif type(value) is float and not math.isfinite(value):
                raise ValueError("nonfinite release JSON")
            elif type(value) is dict:
                pending.extend((part, depth + 1) for pair in value.items() for part in pair)
            elif type(value) is list:
                pending.extend((part, depth + 1) for part in value)
        return result
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid release JSON") from exc


def safe_path(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or len(name.encode("utf-8")) > 1024
        or "\\" in name
        or ":" in name
        or any(ord(c) < 32 for c in name)
        or path.is_absolute()
        or path.as_posix() != name.removesuffix("/")
        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
    ):
        raise ValueError("unowned release archive path")
    return path.as_posix()


def read_archive(
    path: Path,
    *,
    wheel: bool,
    roots: tuple[str, ...] | None = None,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_members: int = MAX_MEMBERS,
) -> dict[str, bytes]:
    raw = read_file(path, max_archive_bytes)
    result: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0

    def add(name, size, regular, directory, stream):
        nonlocal total
        name = safe_path(name)
        if roots is not None and name.split("/", 1)[0] not in roots:
            raise ValueError("release archive contains an unowned top-level directory")
        if name in seen or len(seen) >= max_members:
            raise ValueError("duplicate or excessive release archive entries")
        seen.add(name)
        if directory:
            return
        total += size
        if not regular or size > max_member_bytes or total > max_archive_bytes:
            raise ValueError("unsupported release archive member type or size")
        data = stream.read(size + 1)
        if len(data) != size:
            raise ValueError("release archive member size mismatch")
        result[name] = data

    if wheel:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for item in archive.infolist():
                if item.orig_filename != item.filename:
                    raise ValueError("wheel archive filename was normalized or NUL-truncated")
                kind = stat.S_IFMT(item.external_attr >> 16)
                if (
                    item.flag_bits & 1
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (kind == stat.S_IFDIR and not item.is_dir())
                    or (kind == stat.S_IFREG and item.is_dir())
                ):
                    raise ValueError("unsupported encrypted or linked wheel member")
                with archive.open(item) as stream:
                    add(item.filename, item.file_size, not item.is_dir(), item.is_dir(), stream)
    else:
        # Bound the entire expanded TAR, including hidden PAX/longname headers
        # and padding, before tarfile can allocate or interpret any of them.
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            expanded = compressed.read(max_archive_bytes + 1)
        if len(expanded) > max_archive_bytes:
            raise ValueError("expanded source archive exceeds its bound")
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for item in archive:
                if item.isdir():
                    add(item.name, 0, False, True, None)
                elif item.isfile():
                    with archive.extractfile(item) as stream:
                        add(item.name, item.size, True, False, stream)
                else:
                    raise ValueError("source distribution contains a link or special entry")
    return result
