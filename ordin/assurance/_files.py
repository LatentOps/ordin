"""Read-only, bounded file access anchored to an explicitly authorized directory.

POSIX uses directory descriptors and O_NOFOLLOW. Windows retains non-deletable
directory handles, opens reparse points themselves, and rejects them. Neither
path follows links, opens devices/remote paths, or runs repository code.
"""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
_DEVICES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(10)),
    *(f"LPT{i}" for i in range(10)),
}


class ScopedFileError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def relative_parts(value: str, *, directory: bool = False) -> tuple[str, ...]:
    if directory and value == "":
        return ()
    if not isinstance(value, str) or len(value) > 1024:
        raise ScopedFileError("source_path_unsupported")
    parts = tuple(value.split("/"))
    if any(
        not _COMPONENT.fullmatch(part)
        or part in {".", ".."}
        or part.endswith(".")
        or part.split(".", 1)[0].upper() in _DEVICES
        for part in parts
    ):
        raise ScopedFileError("source_path_unsupported")
    return parts


def _root(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ScopedFileError("authorized_root_must_be_absolute")
    # Reject remote/device namespaces instead of implicitly touching a share.
    if str(value).startswith(("\\\\", "//")) or ".." in value.parts:
        raise ScopedFileError("authorized_root_unsupported")
    if len(str(value)) > 4096 or len(value.parts) > 128:
        raise ScopedFileError("authorized_root_limit")
    if os.name == "nt" and any(
        part.endswith((".", " ")) or ":" in part or part.split(".", 1)[0].upper() in _DEVICES
        for part in value.parts[1:]
    ):
        raise ScopedFileError("authorized_root_unsupported")
    return value


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _safe_stat(info: os.stat_result, *, directory: bool) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ScopedFileError("source_link_rejected")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ScopedFileError("source_type_unsupported")
    if not directory and info.st_nlink != 1:
        raise ScopedFileError("source_hardlink_rejected")


@dataclass(frozen=True)
class DirectoryEntry:
    name: str
    kind: str


def _windows_handle(stack: ExitStack, path: Path, *, directory: bool) -> int:
    import ctypes
    from ctypes import wintypes

    class FileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", wintypes.FILETIME),
            ("accessed", wintypes.FILETIME),
            ("modified", wintypes.FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    kernel = getattr(ctypes, "WinDLL")("kernel32.dll", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    inspect = kernel.GetFileInformationByHandle
    inspect.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
    inspect.restype = wintypes.BOOL
    # OPEN_EXISTING, OPEN_REPARSE_POINT; directories require BACKUP_SEMANTICS.
    # No FILE_SHARE_DELETE pins names; a file also denies concurrent writers.
    handle = create(
        str(path),
        0x80000000,
        3 if directory else 1,
        None,
        3,
        0x00200000 | 0x00100000 | (0x02000000 if directory else 0),
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ScopedFileError("source_unavailable")
    stack.callback(close, handle)
    info = FileInfo()
    if not inspect(handle, ctypes.byref(info)):
        raise ScopedFileError("source_metadata_unavailable")
    if info.attributes & 0x400:
        raise ScopedFileError("source_link_rejected")
    if info.attributes & 0x1000:
        raise ScopedFileError("source_offline_storage_unsupported")
    if bool(info.attributes & 0x10) != directory:
        raise ScopedFileError("source_type_unsupported")
    if not directory and info.links != 1:
        raise ScopedFileError("source_hardlink_rejected")
    return handle


@contextmanager
def _directory(root: Path, relative: str = "") -> Iterator[tuple[int | Path, Path]]:
    root = _root(root)
    parts = relative_parts(relative, directory=True)
    with ExitStack() as stack:
        if os.name == "posix":
            if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
                raise ScopedFileError("source_platform_unsupported")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            # Pin every absolute ancestor as well as the authorized root.
            descriptor = os.open(root.anchor, flags)
            stack.callback(os.close, descriptor)
            for part in (*root.parts[1:], *parts):
                descriptor = os.open(part, flags, dir_fd=descriptor)
                stack.callback(os.close, descriptor)
            _safe_stat(os.fstat(descriptor), directory=True)
            yield descriptor, root.joinpath(*parts)
        elif os.name == "nt":
            path = Path(root.anchor)
            _windows_handle(stack, path, directory=True)
            for part in (*root.parts[1:], *parts):
                if part in {".", ".."}:
                    raise ScopedFileError("source_path_unsupported")
                path = path / part
                _windows_handle(stack, path, directory=True)
            yield path, path
        else:
            raise ScopedFileError("source_platform_unsupported")


def directory_entries(
    root: Path, relative: str = "", *, maximum: int = 256
) -> tuple[DirectoryEntry, ...]:
    if type(maximum) is not int or not 1 <= maximum <= 4096:
        raise ValueError("invalid directory entry budget")
    try:
        with _directory(root, relative) as (directory, _), os.scandir(directory) as iterator:
            result: list[DirectoryEntry] = []
            for entry in iterator:
                if len(result) == maximum:
                    raise ScopedFileError("source_directory_limit")
                try:
                    relative_parts(entry.name)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        kind = "link"
                    elif stat.S_ISDIR(info.st_mode):
                        kind = "directory"
                    elif stat.S_ISREG(info.st_mode):
                        # Cached Windows enumeration metadata may omit nlink.
                        # The reader checks the real handle before reading.
                        kind = "file" if info.st_nlink in {0, 1} else "hardlink"
                    else:
                        kind = "unsupported"
                except (ScopedFileError, OSError):
                    kind = "unsupported"
                result.append(DirectoryEntry(entry.name, kind))
            return tuple(sorted(result, key=lambda entry: entry.name))
    except ScopedFileError:
        raise
    except OSError as exc:
        raise ScopedFileError("source_unavailable") from exc


def read_scoped_file(
    root: Path, relative: str, *, maximum: int = 1_048_576, private: bool = False
) -> bytes:
    parts = relative_parts(relative)
    if type(maximum) is not int or not 1 <= maximum <= 16_777_216:
        raise ValueError("invalid source byte budget")
    try:
        with _directory(root, "/".join(parts[:-1])) as (directory, parent), ExitStack() as stack:
            if os.name == "posix":
                if not isinstance(directory, int):
                    raise ScopedFileError("source_platform_unsupported")
                descriptor = os.open(
                    parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
                stack.callback(os.close, descriptor)
            else:
                import msvcrt

                with ExitStack() as windows_stack:
                    handle = _windows_handle(windows_stack, parent / parts[-1], directory=False)
                    descriptor = getattr(msvcrt, "open_osfhandle")(
                        handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                    )
                    # The CRT descriptor now owns the handle.
                    windows_stack.pop_all()
                stack.callback(os.close, descriptor)
            before = os.fstat(descriptor)
            _safe_stat(before, directory=False)
            if private and os.name == "posix":
                if not isinstance(directory, int):
                    raise ScopedFileError("source_platform_unsupported")
                parent_info = os.fstat(directory)
                if (
                    before.st_uid != os.geteuid()
                    or before.st_mode & 0o077
                    or (parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022)
                ):
                    raise ScopedFileError("protected_profile_permissions_invalid")
            if before.st_size > maximum:
                raise ScopedFileError("source_file_limit")
            content = bytearray()
            while len(content) <= maximum:
                block = os.read(descriptor, min(65536, maximum + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            after = os.fstat(descriptor)
            if len(content) > maximum:
                raise ScopedFileError("source_file_limit")
            if (
                _identity(before) != _identity(after)
                or before.st_size != after.st_size
                or (before.st_mtime_ns != after.st_mtime_ns or before.st_nlink != after.st_nlink)
                or len(content) != after.st_size
            ):
                raise ScopedFileError("source_changed_during_read")
            return bytes(content)
    except ScopedFileError:
        raise
    except OSError as exc:
        raise ScopedFileError("source_unavailable") from exc
