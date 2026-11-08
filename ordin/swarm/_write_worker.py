"""Closed atomic managed-file writer; no arbitrary code or host path execution."""

import base64
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _owned_isolation import file_identity, isolate
from _owned_protocol import WRITE_PROTOCOL, wire

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def open_metadata(name):
    # openat's optional mode vararg is unspecified for O_PATH. Use the fixed
    # x86-64 syscall ABI so every filter-bound argument is supplied, including
    # its kernel-ignored mode; no flags, descriptors or allowances are widened.
    descriptor = _libc.syscall(
        257,
        3,
        ctypes.c_char_p(os.fsencode(name)),
        os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "managed metadata descriptor unavailable")
    return descriptor


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate managed write field")
        result[key] = value
    return result


def current_identity(name, expected):
    try:
        descriptor = open_metadata(name)
    except FileNotFoundError:
        if expected is None:
            return None
        raise ValueError("managed target disappeared") from None
    try:
        actual = file_identity(descriptor)
        if (
            expected is None
            or actual != expected
            or not stat.S_ISREG(actual["mode"])
            or actual["links"] != 1
            or stat.S_IMODE(actual["mode"]) != 0o600
            or actual["size"] > 65536
        ):
            raise ValueError("managed target identity changed")
        return actual
    finally:
        os.close(descriptor)


def main():
    packet = None
    mutation = False
    stage = None
    try:
        raw = sys.stdin.buffer.read(131073)
        if not 1 <= len(raw) <= 131072:
            raise ValueError("managed write frame bound")
        packet = json.loads(raw, object_pairs_hook=unique)
        if type(packet) is not dict or set(packet) != {
            "protocol",
            "request_digest",
            "nonce",
            "action_digest",
            "contract_digest",
            "policy_digest",
            "resource_descriptor",
            "workspace_identity",
            "uid",
            "gid",
            "memory_bytes",
            "cpu_seconds",
            "file_size_bound",
            "filter_digest",
            "name",
            "content",
            "content_digest",
            "max_write_bytes",
            "expected_identity",
            "expected_digest",
            "next_version",
        }:
            raise ValueError("managed write frame shape")
        if (
            packet["protocol"] != WRITE_PROTOCOL
            or packet["request_digest"]
            != hashlib.sha256(
                wire({k: v for k, v in packet.items() if k != "request_digest"})
            ).hexdigest()
        ):
            raise ValueError("managed write frame binding")
        for key in (
            "request_digest",
            "nonce",
            "action_digest",
            "contract_digest",
            "policy_digest",
            "content_digest",
            "filter_digest",
        ):
            if (
                type(packet[key]) is not str
                or len(packet[key]) != 64
                or any(v not in "0123456789abcdef" for v in packet[key])
            ):
                raise ValueError("managed write digest")
        name = packet["name"]
        if (
            type(name) is not str
            or not 1 <= len(name) <= 128
            or any(v in name for v in ("/", "\\", "\0"))
            or name in {".", ".."}
            or name.startswith(".ordin-stage-")
        ):
            raise ValueError("managed flat destination required")
        maximum = packet["max_write_bytes"]
        if type(maximum) is not int or not 1 <= maximum <= 65536:
            raise ValueError("managed write bound")
        content = base64.b64decode(packet["content"], validate=True)
        if (
            len(content) > maximum
            or hashlib.sha256(content).hexdigest() != packet["content_digest"]
        ):
            raise ValueError("managed content binding")
        if type(packet["next_version"]) is not int or not 1 <= packet["next_version"] < 2**53:
            raise ValueError("managed version bound")
        isolation = isolate(packet, "write")
        old_identity = current_identity(name, packet["expected_identity"])
        stage = ".ordin-stage-" + packet["nonce"]
        descriptor = os.open(
            stage,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=3,
        )
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise OSError("managed write did not advance")
                offset += written
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            readback = bytearray()
            while len(readback) <= maximum:
                chunk = os.read(descriptor, min(4096, maximum + 1 - len(readback)))
                if not chunk:
                    break
                readback.extend(chunk)
            if (
                len(readback) != len(content)
                or hashlib.sha256(readback).hexdigest() != packet["content_digest"]
            ):
                raise ValueError("managed staging readback differs")
            new_identity = file_identity(descriptor)
        finally:
            os.close(descriptor)
        flags = 1 if old_identity is None else 2
        if _libc.syscall(
            316,
            3,
            ctypes.c_char_p(os.fsencode(stage)),
            3,
            ctypes.c_char_p(os.fsencode(name)),
            flags,
        ):
            raise OSError(ctypes.get_errno(), "managed atomic publication failed")
        mutation = True
        if old_identity is not None:
            descriptor = open_metadata(stage)
            try:
                displaced = file_identity(descriptor)
                stable = ("device", "inode", "mode", "size", "mtime_ns", "uid", "gid", "links")
                if any(displaced[key] != old_identity[key] for key in stable):
                    raise ValueError("managed destination raced atomic exchange")
            finally:
                os.close(descriptor)
            os.unlink(stage, dir_fd=3)
        stage = None
        os.fsync(3)
        descriptor = open_metadata(name)
        try:
            final = file_identity(descriptor)
            if any(
                final[key] != new_identity[key]
                for key in ("device", "inode", "mode", "size", "mtime_ns", "uid", "gid", "links")
            ):
                raise ValueError("managed published identity differs")
        finally:
            os.close(descriptor)
        response = {
            key: packet[key]
            for key in (
                "protocol",
                "request_digest",
                "nonce",
                "action_digest",
                "contract_digest",
                "policy_digest",
            )
        }
        response.update(
            status="completed",
            identity=final,
            content_digest=packet["content_digest"],
            version=packet["next_version"],
            isolation=isolation,
        )
        frame = wire(response)
        if len(frame) > 8192:
            raise ValueError("managed write receipt bound")
        os.write(1, frame)
        return 0
    except Exception:
        if stage is not None and not mutation:
            try:
                os.unlink(stage, dir_fd=3)
            except OSError:
                pass
        os.write(
            1,
            wire({"protocol": WRITE_PROTOCOL, "status": "unknown" if mutation else "unsupported"}),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
