"""Closed privileged bootstrap. Untrusted Python runs only after parent ACK."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import io
import json
import math
import os
import pathlib
import resource
import signal
import stat
import struct
import sys

PROTOCOL = "ordin.protected_python.v1"
MAX_FRAME = 65536


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def exact(descriptor, count):
    value = bytearray()
    while len(value) < count:
        part = os.read(descriptor, count - len(value))
        if not part:
            raise ValueError("private process frame ended")
        value.extend(part)
    return bytes(value)


def read_frame(descriptor, maximum):
    length = struct.unpack("!I", exact(descriptor, 4))[0]
    if not 1 <= length <= maximum:
        raise ValueError("private process frame limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate private process member")
            result[key] = value
        return result

    result = json.loads(exact(descriptor, length), object_pairs_hook=unique)
    if type(result) is not dict:
        raise ValueError("private process frame object required")
    return result


def send_frame(descriptor, value, maximum=MAX_FRAME):
    raw = wire(value)
    if not 1 <= len(raw) <= maximum:
        raise ValueError("private process reply limit")
    data = struct.pack("!I", len(raw)) + raw
    while data:
        written = os.write(descriptor, data)
        if written <= 0:
            raise OSError("private process channel unavailable")
        data = data[written:]


class BrokerClient:
    """Only the private original parent's MCP route; no TLS or actor selection."""

    def __init__(self):
        self.sequence = 0
        self.initialized = False

    def call(self, method, params=None):
        if type(method) is not str or not 1 <= len(method) <= 128:
            raise ValueError("bounded MCP method required")
        self.sequence += 1
        request = {"jsonrpc": "2.0", "id": self.sequence, "method": method}
        if params is not None:
            request["params"] = params
        send_frame(3, request)
        reply = read_frame(3, MAX_FRAME)
        if reply.get("jsonrpc") != "2.0" or reply.get("id") != self.sequence:
            raise ValueError("private MCP response correlation differs")
        if "error" in reply:
            raise ValueError("protected MCP request refused")
        if "result" not in reply:
            raise ValueError("private MCP response incomplete")
        return reply["result"]

    def initialize(self):
        if not self.initialized:
            result = self.call(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "ordin-confined-agent", "version": "1"},
                },
            )
            if type(result) is not dict or result.get("protocolVersion") != "2025-11-25":
                raise ValueError("protected MCP protocol unavailable")
            send_frame(3, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            self.initialized = True

    def call_tool(self, name, arguments):
        self.initialize()
        if type(name) is not str or type(arguments) is not dict:
            raise ValueError("fixed MCP tool name and arguments required")
        return self.call("tools/call", {"name": name, "arguments": arguments})


def install_filter(libc):
    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    # File operations remain constrained by the private root, readonly mounts,
    # Landlock and the quota-limited scratch filesystem. No sockets, process
    # creation, execution, ptrace, signalling other processes, mount or namespace
    # changes are admitted. In particular ioctl/fallocate cannot bypass output caps.
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
        17,
        18,
        19,
        20,
        24,
        25,
        28,
        32,
        33,
        35,
        39,
        60,
        63,
        77,
        79,
        80,
        81,
        82,
        83,
        84,
        87,
        89,
        90,
        91,
        95,
        96,
        98,
        102,
        104,
        107,
        108,
        110,
        131,
        137,
        138,
        186,
        201,
        202,
        204,
        217,
        218,
        228,
        230,
        231,
        257,
        258,
        262,
        263,
        264,
        267,
        269,
        273,
        292,
        316,
        318,
        332,
        334,
    )
    allow, refuse = 0x7FFF0000, 0x00050000 | errno.EPERM
    code = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    for number in allowed:
        code.extend(((0x15, 0, 1, number), (0x06, 0, 0, allow)))
    # Permit descriptor duplication/readback, never F_SETOWN/F_SETSIG/O_ASYNC:
    # those commands could otherwise signal an unrelated same-UID process.
    safe_fcntl = [(0x20, 0, 0, 24)]
    for command in (0, 1, 2, 3, 1030):
        safe_fcntl.extend(((0x15, 0, 1, command), (0x06, 0, 0, allow)))
    safe_fcntl.append((0x06, 0, 0, refuse))
    code.extend(((0x15, 0, len(safe_fcntl), 72), *safe_fcntl))
    # Only harmless readback prctl operations are permitted.
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
    filters = (Filter * len(code))(*(Filter(*entry) for entry in code))
    program = Program(len(code), filters)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError("seccomp unavailable")
    return hashlib.sha256(wire(code)).hexdigest()


def isolate(packet):
    if sys.platform != "linux" or os.uname().machine != "x86_64" or os.geteuid() != 0:
        raise ValueError("qualified privileged Linux bootstrap required")
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("bootstrap must be single threaded")
    if not stat.S_ISFIFO(os.fstat(0).st_mode):
        raise ValueError("private input pipe required")
    output, error = os.fstat(1), os.fstat(2)
    if (
        not stat.S_ISREG(output.st_mode)
        or output.st_nlink != 0
        or (output.st_dev, output.st_ino) != (error.st_dev, error.st_ino)
        or any(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY for fd in (1, 2))
    ):
        raise ValueError("one anonymous write-only diagnostic file required")
    ipc = packet["ipc_fd"]
    if type(ipc) is not int or not 3 <= ipc <= 4095 or not stat.S_ISSOCK(os.fstat(ipc).st_mode):
        raise ValueError("original private IPC socket required")
    if ipc != 3:
        os.dup2(ipc, 3, inheritable=False)
    for entry in os.listdir("/proc/self/fd"):
        if int(entry) > 3:
            try:
                os.close(int(entry))
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    limits = packet["limits"]
    # Parent validates configuration as typed data; repeat exact wire limits in
    # the closed bootstrap, before accepting them as kernel installation input.
    ranges = {
        "timeout_ms": (1000, 60000),
        "cpu_seconds": (1, 30),
        "memory_mib": (128, 1024),
        "output_bytes": (8192, 1048576),
        "scratch_bytes": (1048576, 32 * 1048576),
        "scratch_inodes": (64, 1024),
        "maximum_calls": (1, 256),
    }
    if (
        type(limits) is not dict
        or set(limits) != set(ranges)
        or any(
            type(limits[key]) is not int or not low <= limits[key] <= high
            for key, (low, high) in ranges.items()
        )
        or limits["scratch_bytes"] % 4096
        or (
            limits["scratch_bytes"] // min(limits["output_bytes"], 65536) + 3
            >= limits["scratch_inodes"]
        )
    ):
        raise ValueError("invalid closed process bounds")
    uid, gid = packet["uid"], packet["gid"]
    if (uid, gid) != (65534, 65534):
        raise ValueError("closed non-root process identity required")
    os.environ.clear()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    libc.unshare.argtypes = [ctypes.c_int]
    libc.mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    if libc.unshare(0x00020000 | 0x40000000):
        raise OSError("private mount/network namespaces unavailable")
    if libc.mount(None, b"/", None, 16384 | (1 << 18), None):
        raise OSError("private mount propagation unavailable")
    test = packet.get("test")
    scratch_name = "/scratch" if test is not None else "/tmp"
    if test is not None:
        # Only original parent-selected, presealed roots reach this bootstrap.
        # Never mount the host/venv root or discover plugins before isolation.
        mounts = (
            (test["snapshot"], test["project_root"], True),
            (test["runtime_root"], test["runtime_root"], False),
            (test["runtime_root"] + "/stdlib", test["stdlib_virtual"], False),
        )
        for source, virtual, noexec in mounts:
            target = pathlib.Path(packet["jail"]) / virtual.lstrip("/")
            target.mkdir(mode=0o755, parents=True, exist_ok=True)
            if libc.mount(os.fsencode(source), os.fsencode(target), None, 4096, None):
                raise OSError("fixed readonly runtime mount unavailable")
            flags = 4096 | 32 | 1 | 2 | 4 | (8 if noexec else 0)
            if libc.mount(None, os.fsencode(target), None, flags, None):
                raise OSError("fixed runtime readonly remount unavailable")
    scratch = os.fsencode(packet["jail"] + scratch_name)
    options = (
        "size="
        + str(limits["scratch_bytes"])
        + ",nr_inodes="
        + str(limits["scratch_inodes"])
        + ",mode=0700,uid=65534,gid=65534"
    ).encode()
    if libc.mount(b"tmpfs", scratch, b"tmpfs", 2 | 4 | 8, options):
        raise OSError("quota-limited scratch filesystem unavailable")
    os.chroot(packet["jail"])
    os.chdir("/")
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError("no-new-privileges unavailable")
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        raise OSError("Landlock unavailable")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]

    mask = (1 << 13) - 1
    rules = Ruleset(mask)
    ruleset = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if ruleset < 0:
        raise OSError("Landlock ruleset unavailable")
    try:
        scopes = [(scratch_name, mask & ~1)]
        if test is not None:
            scopes.extend(
                (path, 4 | 8)
                for path in (
                    test["project_root"],
                    test["runtime_root"],
                    test["stdlib_virtual"],
                )
            )
            scopes.append(("/pytest.ini", 4))
        for path, access in scopes:
            parent = os.open(path, os.O_PATH)
            try:
                rule = Beneath(access, parent)
                if libc.syscall(445, ruleset, 1, ctypes.byref(rule), 0):
                    raise OSError("Landlock fixed process scope unavailable")
            finally:
                os.close(parent)
        if libc.syscall(446, ruleset, 0):
            raise OSError("Landlock restriction unavailable")
    finally:
        os.close(ruleset)
    checks = {}
    # Test before UID drop: ordinary DAC must not masquerade as Landlock.
    for label, flags in (("host_read_denied", os.O_RDONLY), ("project_write_denied", os.O_WRONLY)):
        try:
            fd = os.open("/forbidden", flags)
        except OSError as exc:
            if exc.errno != errno.EACCES:
                raise OSError("filesystem denial probe inconclusive") from None
            checks[label] = True
        else:
            os.close(fd)
            raise OSError("filesystem denial probe failed")
    if test is not None:
        # This is a real attempted write to the mounted project, before DAC
        # privilege drop. A nonwritable mode bit is not sufficient evidence.
        try:
            fd = os.open(
                test["project_root"] + "/.ordin-write-probe", os.O_WRONLY | os.O_CREAT, 0o600
            )
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EROFS):
                raise OSError("readonly snapshot probe inconclusive") from None
        else:
            os.close(fd)
            raise OSError("readonly project mount failed")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise ValueError("non-root identity installation differs")

    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header, capabilities = CapHeader(0x20080522, 0), (CapData * 2)()
    if libc.syscall(126, ctypes.byref(header), ctypes.byref(capabilities)):
        raise OSError("capability drop unavailable")
    for kind, maximum in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_AS, limits["memory_mib"] * 1048576),
        (resource.RLIMIT_CPU, limits["cpu_seconds"]),
        (resource.RLIMIT_NPROC, 1),
        (resource.RLIMIT_NOFILE, 16),
        (resource.RLIMIT_FSIZE, limits["output_bytes"]),
    ):
        resource.setrlimit(kind, (maximum, maximum))
    kernel_limits = {
        key: list(resource.getrlimit(kind))
        for key, kind in (
            ("cpu_seconds", resource.RLIMIT_CPU),
            ("address_space", resource.RLIMIT_AS),
            ("processes", resource.RLIMIT_NPROC),
            ("descriptors", resource.RLIMIT_NOFILE),
            ("output_file", resource.RLIMIT_FSIZE),
            ("core", resource.RLIMIT_CORE),
        )
    }
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    filter_digest = install_filter(libc)
    if libc.prctl(21, 0, 0, 0, 0) != 2 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise ValueError("kernel restriction readback differs")
    for label, number, arguments in (
        ("socket_denied", 41, (2, 1, 0)),
        ("fork_denied", 57, ()),
        ("exec_denied", 59, (ctypes.c_char_p(b"/never-executable"), None, None)),
        ("descriptor_signal_denied", 72, (3, 8, os.getppid())),
    ):
        result = libc.syscall(number, *arguments)
        if label == "fork_denied" and result == 0:
            os._exit(126)
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            raise OSError("process/network denial probe failed")
        checks[label] = True
    try:
        os.ftruncate(1, limits["output_bytes"] * 2)
    except OSError as exc:
        if exc.errno != errno.EFBIG:
            raise OSError("output ceiling probe inconclusive") from None
        checks["output_limit_enforced"] = True
    else:
        raise OSError("output ceiling not enforced")
    libc.mmap.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_longlong,
    ]
    libc.mmap.restype = ctypes.c_void_p
    allocation = libc.mmap(None, limits["memory_mib"] * 2097152, 3, 0x22, -1, 0)
    if allocation != ctypes.c_void_p(-1).value or ctypes.get_errno() != errno.ENOMEM:
        raise OSError("memory ceiling probe failed")
    checks["memory_limit_enforced"] = True
    capacity = os.statvfs(scratch_name)
    if (
        capacity.f_blocks * capacity.f_frsize > limits["scratch_bytes"]
        or capacity.f_files > limits["scratch_inodes"]
    ):
        raise OSError("scratch quota readback differs")
    paths = []
    try:
        block = b"x" * min(limits["output_bytes"], 65536)
        for index in range(limits["scratch_inodes"] + 1):
            path = scratch_name + "/bytes-" + str(index)
            try:
                with open(path, "wb") as scratch_writer:
                    paths.append(path)
                    scratch_writer.write(block)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise OSError("scratch byte quota probe inconclusive") from None
                checks["scratch_byte_quota_enforced"] = True
                break
        if "scratch_byte_quota_enforced" not in checks:
            raise OSError("scratch byte quota not reached")
    finally:
        for path in paths:
            os.unlink(path)
    paths = []
    try:
        for index in range(limits["scratch_inodes"] + 1):
            path = scratch_name + "/inode-" + str(index)
            try:
                with open(path, "wb"):
                    paths.append(path)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise OSError("scratch inode quota probe inconclusive") from None
                checks["scratch_inode_quota_enforced"] = True
                break
        if "scratch_inode_quota_enforced" not in checks:
            raise OSError("scratch inode quota not reached")
    finally:
        for path in paths:
            os.unlink(path)
    return {
        "uid": uid,
        "gid": gid,
        "landlock_abi": abi,
        "seccomp": 2,
        "no_new_privileges": 1,
        "filter_digest": filter_digest,
        "limits": limits,
        "kernel_limits": kernel_limits,
        "environment_empty": not os.environ,
        "checks": checks,
    }


def main():
    packet = None
    try:
        packet = read_frame(0, 262144)
        fields = {
            "protocol",
            "mode",
            "nonce",
            "binding",
            "jail",
            "ipc_fd",
            "uid",
            "gid",
            "limits",
            "program",
        }
        if packet.get("mode") == "pytest":
            fields.add("test")
        if (
            set(packet) != fields
            or packet["protocol"] != PROTOCOL
            or packet["mode"] not in {"agent", "pytest"}
        ):
            raise ValueError("closed bootstrap packet required")
        if packet["mode"] == "pytest":
            test = packet["test"]
            if (
                type(test) is not dict
                or set(test)
                != {
                    "project_root",
                    "snapshot",
                    "snapshot_digest",
                    "runtime_root",
                    "runtime_digest",
                    "stdlib_virtual",
                    "selectors",
                }
                or any(
                    type(test[key]) is not str or not test[key].startswith("/")
                    for key in ("project_root", "snapshot", "runtime_root", "stdlib_virtual")
                )
            ):
                raise ValueError("closed fixed-test settings required")
        if type(packet["program"]) is not str or len(packet["program"].encode()) > 65536:
            raise ValueError("bounded pinned agent source required")
        isolation = isolate(packet)
        send_frame(
            3,
            {
                "protocol": PROTOCOL,
                "phase": "ready",
                "nonce": packet["nonce"],
                "binding": packet["binding"],
                "isolation": isolation,
            },
            16384,
        )
        ack = read_frame(3, 4096)
        if ack != {"protocol": PROTOCOL, "phase": "start", "binding": packet["binding"]}:
            raise ValueError("original parent start acknowledgement required")
        os.close(0)
    except Exception:
        try:
            send_frame(3, {"protocol": PROTOCOL, "phase": "unsupported"}, 4096)
        except Exception:
            pass
        return 2
    # No repository or agent code was imported, compiled or executed before the
    # parent retained actual isolation evidence and acknowledged this transition.
    try:
        if packet["mode"] == "pytest":
            os.close(3)  # Tests cannot access the broker at all.
            test = packet["test"]
            os.environ.update(
                {
                    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    "PYTEST_ADDOPTS": "",
                    "TMPDIR": "/scratch",
                    "HOME": "/scratch",
                }
            )
            sys.dont_write_bytecode = True
            sys.path[:] = [
                test["runtime_root"] + "/site",
                test["stdlib_virtual"],
                test["stdlib_virtual"] + "/lib-dynload",
                test["project_root"],
            ]
            sys.path_importer_cache.clear()
            os.chdir(test["project_root"])
            # This is deliberately after isolation, retained readiness and ACK.
            import pytest

            return int(
                pytest.main(
                    [
                        "-s",
                        "-q",
                        "--noconftest",
                        "-p",
                        "no:cacheprovider",
                        "-c",
                        "/pytest.ini",
                        "--rootdir",
                        test["project_root"],
                        "--confcutdir",
                        test["project_root"],
                        "--log-file",
                        "/scratch/pytest.log",
                        "--basetemp",
                        "/scratch/pytest",
                        *test["selectors"],
                    ]
                )
            )
        program = compile(packet["program"], "/agent.py", "exec", dont_inherit=True)
        exec(
            program,
            {
                "__name__": "__main__",
                "__file__": "/agent.py",
                "mcp": BrokerClient(),
                "json": json,
                "math": math,
                "io": io,
                "Path": pathlib.Path,
            },
        )
        return 0
    except SystemExit as error:
        return error.code if type(error.code) is int and 0 <= error.code <= 255 else 1
    except BaseException:
        # The untrusted program can emit arbitrary diagnostics itself. This
        # fixed message discloses no host paths or exception/local-frame data.
        os.write(2, b"untrusted workload did not complete normally\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
