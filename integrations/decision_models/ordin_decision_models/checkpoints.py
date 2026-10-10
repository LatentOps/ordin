"""Bounded local checkpoint pinning; no Hub lookup or executable model files."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from ordin.assurance._files import (
    _directory,
    _safe_stat,
    _windows_handle,
    directory_entries,
    read_scoped_file,
    relative_parts,
)
from ordin.assurance._json import digest


def _checkpoint_json(raw: bytes) -> dict:
    """Tokenizer vocabularies exceed ordinary advisory-record limits."""
    if len(raw) > 16_777_216:
        raise ValueError("checkpoint JSON byte budget exceeded")
    text = raw.decode("utf-8")
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 32:
                raise ValueError("checkpoint JSON nesting budget exceeded")
        elif char in "]}":
            depth -= 1

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("checkpoint JSON duplicate key")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("checkpoint JSON nonfinite number")

    result = json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite)
    if not isinstance(result, dict):
        raise ValueError("checkpoint JSON root must be object")
    pending, nodes = [result], 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > 2_000_000:
            raise ValueError("checkpoint JSON node budget exceeded")
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and (
            len(value) > 65536 or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
        ):
            raise ValueError("checkpoint JSON text budget exceeded")
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("checkpoint JSON nonfinite number")
        elif type(value) is int and value.bit_length() > 128:
            raise ValueError("checkpoint JSON integer budget exceeded")
    return result


REQUIRED = frozenset(
    {
        "rl_agent_config.json",
        "model.safetensors",
        "encoder/config.json",
        "tokenizer/tokenizer.json",
        "tokenizer/tokenizer_config.json",
    }
)
OPTIONAL = frozenset(
    {"tokenizer/special_tokens_map.json", "tokenizer/added_tokens.json", "README.md", "LICENSE"}
)


def hash_local_file(root: Path, relative: str, *, maximum: int = 1_073_741_824) -> tuple[str, int]:
    """Stream a regular unlinked file, retaining pinned ancestors while reading."""
    parts = relative_parts(relative)
    with _directory(root, "/".join(parts[:-1])) as (directory, parent), ExitStack() as stack:
        if isinstance(directory, int):
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            stack.callback(os.close, fd)
        else:
            import msvcrt

            with ExitStack() as handles:
                handle = _windows_handle(handles, parent / parts[-1], directory=False)
                fd = getattr(msvcrt, "open_osfhandle")(
                    handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                )
                handles.pop_all()
            stack.callback(os.close, fd)
        before = os.fstat(fd)
        _safe_stat(before, directory=False)
        if before.st_size > maximum:
            raise ValueError("local artifact byte budget exceeded")
        fingerprint, consumed = hashlib.sha256(), 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - consumed))
            if not block:
                break
            consumed += len(block)
            if consumed > maximum:
                raise ValueError("local artifact byte budget exceeded")
            fingerprint.update(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_nlink,
        ) or consumed != after.st_size:
            raise ValueError("local artifact changed while hashing")
        return fingerprint.hexdigest(), consumed


@dataclass(frozen=True)
class LocalCheckpoint:
    root: Path
    revision: str
    files: tuple[tuple[str, str], ...]
    device: str = "cpu"
    max_tokens: int = 512
    max_total_bytes: int = 2_147_483_648

    def __post_init__(self):
        if (
            not isinstance(self.root, Path)
            or not self.root.is_absolute()
            or not re.fullmatch(r"[a-f0-9]{40}", self.revision)
        ):
            raise ValueError("local checkpoint requires absolute selected root and pinned revision")
        if not isinstance(self.files, tuple) or not 5 <= len(self.files) <= 9:
            raise ValueError("local checkpoint manifest must be bounded")
        names = set()
        for name, sha in self.files:
            relative_parts(name)
            if name in names or not re.fullmatch(r"[a-f0-9]{64}", sha):
                raise ValueError("checkpoint manifest duplicate or invalid digest")
            names.add(name)
        if not REQUIRED <= names or names - REQUIRED - OPTIONAL:
            raise ValueError(
                "checkpoint needs complete inert local artifacts; executable/unknown files refused"
            )
        if (
            self.device not in {"cpu", "cuda:0", "mps", "xpu:0"}
            or type(self.max_tokens) is not int
            or not 128 <= self.max_tokens <= 8192
            or type(self.max_total_bytes) is not int
            or not 1024 <= self.max_total_bytes <= 4_294_967_296
        ):
            raise ValueError("checkpoint device/resource budget invalid")

    @property
    def manifest_digest(self):
        return digest(
            "laya_checkpoint",
            {
                "root_digest": hashlib.sha256(str(self.root).encode()).hexdigest(),
                "revision": self.revision,
                "files": sorted(self.files),
                "device": self.device,
                "max_tokens": self.max_tokens,
                "max_total_bytes": self.max_total_bytes,
            },
        )

    def worker_dict(self):
        return {
            "root": str(self.root),
            "revision": self.revision,
            "files": [list(item) for item in self.files],
            "device": self.device,
            "max_tokens": self.max_tokens,
            "max_total_bytes": self.max_total_bytes,
        }

    def verify(self) -> None:
        actual = set()
        for relative in ("", "encoder", "tokenizer"):
            for item in directory_entries(self.root, relative, maximum=32):
                name = relative + "/" + item.name if relative else item.name
                if item.kind == "directory" and name in {"encoder", "tokenizer"}:
                    continue
                if item.kind != "file":
                    raise ValueError("checkpoint linked/special/unknown directory refused")
                actual.add(name)
        if actual != {name for name, _ in self.files}:
            raise ValueError("checkpoint artifacts do not exactly match selected manifest")
        total = 0
        for name, expected in self.files:
            sha, size = hash_local_file(self.root, name)
            if sha != expected:
                raise ValueError("local checkpoint differs from reviewed hash")
            total += size
            if total > self.max_total_bytes:
                raise ValueError("checkpoint total byte budget exceeded")
        for name in (
            "rl_agent_config.json",
            "encoder/config.json",
            "tokenizer/tokenizer_config.json",
            "tokenizer/tokenizer.json",
        ):
            packet = _checkpoint_json(read_scoped_file(self.root, name, maximum=16_777_216))
            pending = [packet]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if name != "tokenizer/tokenizer.json" and any(
                        key in value
                        for key in ("auto_map", "custom_pipelines", "trust_remote_code")
                    ):
                        raise ValueError("checkpoint executable/custom model configuration refused")
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
            if name == "tokenizer/tokenizer_config.json" and (
                packet.get("tokenizer_class") != "PreTrainedTokenizerFast"
                or isinstance(packet.get("extra_special_tokens"), list)
            ):
                raise ValueError(
                    "tokenizer configuration requires mutation; prepare/review/pin it separately"
                )

    @classmethod
    def from_worker_dict(cls, packet):
        if not isinstance(packet, dict) or set(packet) != {
            "root",
            "revision",
            "files",
            "device",
            "max_tokens",
            "max_total_bytes",
        }:
            raise ValueError("checkpoint worker input malformed")
        return cls(
            Path(packet["root"]),
            packet["revision"],
            tuple(tuple(item) for item in packet["files"]),
            packet["device"],
            packet["max_tokens"],
            packet["max_total_bytes"],
        )
