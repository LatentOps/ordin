"""Closed standalone file-read worker; invoked only by the protected broker."""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import resource
import signal
import stat
import sys

PROTOCOL = "ordin.swarm.linux_file_read.v1"
FILTER_DIGEST = "39ba6d1343b819518f4aa0465b533a048e3b174de064abf36cc9f356e8d0f261"


def wire(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def identity(descriptor):
    info = os.fstat(descriptor)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


def isolate(packet):
    if sys.platform != "linux" or os.uname().machine != "x86_64" or sys.byteorder != "little":
        raise ValueError("unsupported kernel")
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("worker is not single threaded")
    if not stat.S_ISFIFO(os.fstat(0).st_mode):
        raise ValueError("worker input must be a private pipe")
    output = os.fstat(1)
    if (
        not stat.S_ISREG(output.st_mode)
        or output.st_nlink != 0
        or (output.st_dev, output.st_ino) != (os.fstat(2).st_dev, os.fstat(2).st_ino)
    ):
        raise ValueError("worker output must be one private anonymous file")
    if (
        fcntl.fcntl(1, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY
        or fcntl.fcntl(2, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY
    ):
        raise ValueError("worker output descriptors must be write only")
    descriptor = packet["file_descriptor"]
    if type(descriptor) is not int or not 3 <= descriptor <= 255:
        raise ValueError("invalid file descriptor")
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or identity(descriptor) != packet["file_identity"]:
        raise ValueError("file binding mismatch")
    if fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("file descriptor is not read only")
    if descriptor != 3:
        os.dup2(descriptor, 3, inheritable=False)
        os.close(descriptor)
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 3:
            try:
                os.close(int(name))
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    uid, gid = packet["uid"], packet["gid"]
    if any(type(value) is not int or not 1 <= value < 2**31 for value in (uid, gid)):
        raise ValueError("non-root worker identity required")
    os.environ.clear()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError("no-new-privileges unavailable")
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        raise OSError("Landlock unavailable")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    rules = Ruleset((1 << 13) - 1)
    ruleset = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if ruleset < 0:
        raise OSError("Landlock ruleset unavailable")
    try:
        if libc.syscall(446, ruleset, 0):
            raise OSError("Landlock restriction unavailable")
    finally:
        os.close(ruleset)
    checks = {}
    # Probe while still using the installer account, which owns the 0600 worker.
    # Otherwise DAC after privilege drop could masquerade as a Landlock denial.
    for label, flags in (
        ("new_path_read_denied", os.O_RDONLY),
        ("new_path_write_denied", os.O_WRONLY),
    ):
        try:
            opened = os.open(sys.argv[0], flags)
        except OSError as error:
            if error.errno != errno.EACCES:
                raise OSError("Landlock probe inconclusive") from None
            checks[label] = True
        else:
            os.close(opened)
            raise OSError("Landlock probe failed")
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise ValueError("worker identity differs")
    memory = packet["memory_bytes"]
    cpu = packet["cpu_seconds"]
    output_bound = packet["max_output_frame_bytes"]
    if (
        type(memory) is not int
        or not 64 * 1048576 <= memory <= 256 * 1048576
        or type(cpu) is not int
        or not 1 <= cpu <= 10
    ):
        raise ValueError("worker limits invalid")
    if type(output_bound) is not int or not 8192 <= output_bound <= 139264:
        raise ValueError("worker output frame ceiling invalid")
    for kind, maximum in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_AS, memory),
        (resource.RLIMIT_CPU, cpu),
        (resource.RLIMIT_NPROC, 1),
        (resource.RLIMIT_NOFILE, 4),
        (resource.RLIMIT_FSIZE, output_bound),
    ):
        resource.setrlimit(kind, (maximum, maximum))
    limits = {
        "cpu_seconds": list(resource.getrlimit(resource.RLIMIT_CPU)),
        "memory_bytes": list(resource.getrlimit(resource.RLIMIT_AS)),
        "processes": list(resource.getrlimit(resource.RLIMIT_NPROC)),
        "descriptors": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "core_bytes": list(resource.getrlimit(resource.RLIMIT_CORE)),
        "output_frame_bytes": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
    }
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    try:
        os.ftruncate(1, output_bound * 2)
    except OSError as error:
        if error.errno != errno.EFBIG:
            raise OSError("output ceiling probe inconclusive") from None
        checks["output_frame_ceiling_enforced"] = True
    else:
        raise OSError("output ceiling probe failed")

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    allowed = (
        0,
        1,
        3,
        5,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        24,
        25,
        35,
        39,
        60,
        96,
        98,
        102,
        104,
        107,
        108,
        110,
        131,
        186,
        201,
        202,
        228,
        230,
        231,
        318,
    )
    allow, refuse = 0x7FFF0000, 0x00050000 | errno.EPERM
    code = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in allowed:
        code.extend(((0x15, 0, 1, number), (0x06, 0, 0, allow)))
    code.extend(
        (
            (0x15, 1, 0, 157),
            (0x06, 0, 0, refuse),
            (0x20, 0, 0, 16),
            (0x15, 2, 0, 21),
            (0x15, 1, 0, 39),
            (0x06, 0, 0, refuse),
            (0x06, 0, 0, allow),
        )
    )
    profile_digest = hashlib.sha256(wire(code)).hexdigest()
    if profile_digest != FILTER_DIGEST:
        raise ValueError("kernel filter identity mismatch")
    filters = (Filter * len(code))(*(Filter(*entry) for entry in code))
    program = Program(len(code), filters)
    mmap = libc.mmap
    mmap.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_longlong,
    ]
    mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError("seccomp unavailable")
    if libc.prctl(21, 0, 0, 0, 0) != 2 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError("kernel restriction readback differs")
    for label, number, arguments in (
        ("network_socket_denied", 41, (2, 1, 0)),
        ("process_creation_denied", 57, ()),
        ("executable_launch_denied", 59, (ctypes.c_char_p(b"/never-executable"), None, None)),
    ):
        result = libc.syscall(number, *arguments)
        if label == "process_creation_denied" and result == 0:
            os._exit(126)
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            if label == "network_socket_denied" and result >= 0:
                os.close(result)
            raise OSError("seccomp probe failed")
        checks[label] = True
    allocation = mmap(None, memory * 2, 3, 0x22, -1, 0)
    if allocation != ctypes.c_void_p(-1).value or ctypes.get_errno() != errno.ENOMEM:
        if allocation != ctypes.c_void_p(-1).value:
            libc.munmap(allocation, memory * 2)
        raise OSError("memory ceiling probe failed")
    checks["memory_ceiling_enforced"] = True
    try:
        os.write(3, b"")
    except OSError as error:
        if error.errno != errno.EBADF:
            raise OSError("read-only descriptor probe inconclusive") from None
        checks["descriptor_write_denied"] = True
    else:
        raise OSError("descriptor unexpectedly writable")
    return {
        "landlock_abi": abi,
        "seccomp_mode": 2,
        "no_new_privileges": 1,
        "filter_digest": profile_digest,
        "uid": uid,
        "gid": gid,
        "limits": limits,
        "environment_empty": not os.environ,
        "checks": checks,
        "filesystem_scope": "preopened_exact_read_only_file",
        "network_access": "denied",
        "process_creation": "denied",
        "executable_launch": "denied",
    }


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if not 1 <= len(raw) <= 16384:
            raise ValueError("worker frame size")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate worker key")
                result[key] = value
            return result

        packet = json.loads(raw, object_pairs_hook=unique)
        if type(packet) is not dict or set(packet) != {
            "protocol",
            "request_digest",
            "nonce",
            "action_digest",
            "contract_digest",
            "policy_digest",
            "file_descriptor",
            "file_identity",
            "uid",
            "gid",
            "memory_bytes",
            "cpu_seconds",
            "max_payload_bytes",
            "max_output_frame_bytes",
        }:
            raise ValueError("worker frame shape")
        material = {key: value for key, value in packet.items() if key != "request_digest"}
        if (
            packet["protocol"] != PROTOCOL
            or hashlib.sha256(wire(material)).hexdigest() != packet["request_digest"]
        ):
            raise ValueError("worker frame binding")
        for key in ("request_digest", "nonce", "action_digest", "contract_digest", "policy_digest"):
            if (
                type(packet[key]) is not str
                or len(packet[key]) != 64
                or any(char not in "0123456789abcdef" for char in packet[key])
            ):
                raise ValueError("worker binding digest")
        maximum = packet["max_payload_bytes"]
        if type(maximum) is not int or not 1 <= maximum <= 65536:
            raise ValueError("worker output budget")
        isolation = isolate(packet)
        os.lseek(3, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(3, min(4096, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if identity(3) != packet["file_identity"] or len(data) > maximum:
            status, encoded, payload_hash, count = "denied", "", None, 0
        else:
            status, encoded = "completed", base64.b64encode(data).decode("ascii")
            payload_hash, count = hashlib.sha256(data).hexdigest(), len(data)
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
            status=status,
            payload=encoded,
            payload_digest=payload_hash,
            payload_bytes=count,
            file_identity=packet["file_identity"],
            isolation=isolation,
        )
        sys.stdout.buffer.write(wire(response))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        sys.stdout.buffer.write(wire({"protocol": PROTOCOL, "status": "unsupported"}))
        sys.stdout.buffer.flush()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
