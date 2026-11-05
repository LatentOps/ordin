"""Protected content-addressed bytes; gateway permissions do not sandbox bypasses."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from threading import RLock
from typing import Protocol

from .events import _hex


class ArtifactStoreCapacityError(ValueError):
    """A bounded rejection before any storage mutation."""


class ArtifactBlobStore(Protocol):
    def put(self, content: bytes) -> str: ...
    def read(self, content_digest: str, byte_length: int) -> bytes: ...
    def remove(self, content_digest: str) -> None: ...


class MemoryArtifactStore:
    """Explicit bounded in-memory fixture, private to its protected host owner."""

    def __init__(self, *, max_bytes: int = 16 * 1024 * 1024, max_blobs: int = 4096) -> None:
        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= 128 * 1024 * 1024
            or type(max_blobs) is not int
            or not 1 <= max_blobs <= 16384
        ):
            raise ValueError("invalid bounded artifact store")
        self._maximum, self._count = max_bytes, max_blobs
        self._blobs: dict[str, bytes] = {}
        self._bytes = 0
        self._lock = RLock()

    def put(self, content: bytes) -> str:
        if type(content) is not bytes or len(content) > 1048576:
            raise ValueError("bounded artifact bytes required")
        key = hashlib.sha256(content).hexdigest()
        with self._lock:
            if key in self._blobs:
                self.read(key, len(content))
                return key
            if len(self._blobs) >= self._count or self._bytes + len(content) > self._maximum:
                raise ArtifactStoreCapacityError("artifact byte store capacity reached")
            self._blobs[key] = content
            self._bytes += len(content)
            return key

    def read(self, content_digest: str, byte_length: int) -> bytes:
        _hex(content_digest, "artifact digest")
        if type(byte_length) is not int or not 0 <= byte_length <= 1048576:
            raise ValueError("invalid artifact byte length")
        with self._lock:
            content = self._blobs.get(content_digest)
            if (
                content is None
                or len(content) != byte_length
                or hashlib.sha256(content).hexdigest() != content_digest
            ):
                raise ValueError("artifact backing bytes unavailable or changed")
            return content

    def remove(self, content_digest: str) -> None:
        _hex(content_digest, "artifact digest")
        with self._lock:
            old = self._blobs.pop(content_digest, None)
            if old is not None:
                self._bytes -= len(old)


class FilesystemArtifactStore:
    """POSIX descriptor-relative immutable blobs in an explicit private directory.

    The host owns the directory. This does not stop a process with raw access to
    the host's account/directory; such access remains outside this gateway.
    Windows and platforms lacking no-follow/dir-fd controls fail closed.
    """

    def __init__(
        self, root: Path, *, max_bytes: int = 16 * 1024 * 1024, max_blobs: int = 4096
    ) -> None:
        if (
            os.name != "posix"
            or os.open not in os.supports_dir_fd
            or os.unlink not in os.supports_dir_fd
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
        ):
            raise ValueError(
                "filesystem artifact backend requires POSIX no-follow directory handles"
            )
        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= 128 * 1024 * 1024
            or type(max_blobs) is not int
            or not 1 <= max_blobs <= 16384
        ):
            raise ValueError("invalid bounded filesystem artifact store")
        path = Path(root).absolute()
        if path.resolve(strict=True) != path:
            raise ValueError("artifact root must be an explicit canonical private directory")
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError("artifact root must be owned and private to the protected host")
            # Existing bytes require explicit host reconciliation; do not silently
            # reconstruct identities or quotas from an arbitrary directory.
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise ValueError("artifact root must be empty at initial enrollment")
        except Exception:
            os.close(descriptor)
            raise
        self._fd = descriptor
        self._maximum, self._count = max_bytes, max_blobs
        self._known: dict[str, int] = {}
        self._bytes = 0
        self._lock = RLock()
        self._fault = False

    def _open(self) -> int:
        if self._fd < 0 or self._fault:
            raise ValueError("artifact filesystem store is closed")
        return self._fd

    @staticmethod
    def _name(content_digest: str) -> str:
        return _hex(content_digest, "artifact digest") + ".blob"

    def put(self, content: bytes) -> str:
        if type(content) is not bytes or len(content) > 1048576:
            raise ValueError("bounded artifact bytes required")
        key = hashlib.sha256(content).hexdigest()
        with self._lock:
            parent = self._open()
            if key in self._known:
                self.read(key, len(content))
                return key
            if len(self._known) >= self._count or self._bytes + len(content) > self._maximum:
                raise ArtifactStoreCapacityError("artifact filesystem capacity reached")
            created = False
            try:
                descriptor = os.open(
                    self._name(key),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent,
                )
                created = True
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(parent)
            except OSError:
                self._fault = True
                if created:
                    try:
                        os.unlink(self._name(key), dir_fd=parent)
                    except OSError:
                        pass
                raise ValueError("artifact filesystem write failed or conflicted") from None
            self._known[key] = len(content)
            self._bytes += len(content)
            return key

    def read(self, content_digest: str, byte_length: int) -> bytes:
        name = self._name(content_digest)
        if type(byte_length) is not int or not 0 <= byte_length <= 1048576:
            raise ValueError("invalid artifact byte length")
        with self._lock:
            if self._known.get(content_digest) != byte_length:
                raise ValueError("unknown artifact filesystem version")
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=self._open(),
                )
                with os.fdopen(descriptor, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) & 0o077
                        or info.st_nlink != 1
                        or info.st_size != byte_length
                    ):
                        raise ValueError("artifact filesystem boundary changed")
                    content = stream.read(byte_length + 1)
            except OSError:
                raise ValueError("artifact filesystem read failed") from None
            if len(content) != byte_length or hashlib.sha256(content).hexdigest() != content_digest:
                raise ValueError("artifact filesystem bytes changed")
            return content

    def remove(self, content_digest: str) -> None:
        name = self._name(content_digest)
        with self._lock:
            length = self._known.get(content_digest)
            if length is None:
                return
            self.read(content_digest, length)
            try:
                os.unlink(name, dir_fd=self._open())
                os.fsync(self._open())
            except OSError:
                raise ValueError("artifact filesystem deletion failed") from None
            del self._known[content_digest]
            self._bytes -= length

    def close(self) -> None:
        with self._lock:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
