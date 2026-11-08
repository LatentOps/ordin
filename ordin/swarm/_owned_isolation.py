"""Kernel installation shared only by the immutable owned write/HTTP workers."""

import ctypes
import errno
import fcntl
import os
import resource
import signal
import stat
import sys

from _owned_protocol import FIONBIO, filter_code, filter_digest


def file_identity(descriptor):
    info = os.fstat(descriptor)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "links": info.st_nlink,
    }


def isolate(packet, mode):
    if sys.platform != "linux" or os.uname().machine != "x86_64" or sys.byteorder != "little":
        raise ValueError("unsupported owned-worker kernel")
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("owned worker must be single threaded")
    incoming, outgoing = os.fstat(0), os.fstat(1)
    if (
        not stat.S_ISREG(incoming.st_mode)
        or incoming.st_nlink != 0
        or fcntl.fcntl(0, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or not stat.S_ISREG(outgoing.st_mode)
        or outgoing.st_nlink != 0
        or (outgoing.st_dev, outgoing.st_ino) != (os.fstat(2).st_dev, os.fstat(2).st_ino)
        or any(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY for fd in (1, 2))
    ):
        raise ValueError("owned worker requires private one-way control/output files")
    descriptor = packet["resource_descriptor"]
    if type(descriptor) is not int or not 3 <= descriptor <= 255:
        raise ValueError("invalid owned resource descriptor")
    info = os.fstat(descriptor)
    uid, gid = packet["uid"], packet["gid"]
    if any(type(value) is not int or not 1 <= value < 2**31 for value in (uid, gid)):
        raise ValueError("non-root owned worker identity required")
    if mode == "write":
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700
            or [info.st_dev, info.st_ino] != packet["workspace_identity"]
        ):
            raise ValueError("managed directory binding differs")
    elif mode != "http" or not stat.S_ISSOCK(info.st_mode):
        raise ValueError("owned HTTP requires a preconnected socket")
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
    os.environ.clear()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError("no-new-privileges unavailable")
    abi = libc.syscall(444, None, 0, 1)
    if abi < 1:
        raise OSError("owned Landlock unavailable")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathBeneath(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 8192
    if abi >= 3:
        handled |= 16384
    rules = Ruleset(handled)
    ruleset = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if ruleset < 0:
        raise OSError("owned Landlock ruleset unavailable")
    try:
        if mode == "write":
            # Same-directory rename needs no cross-directory REFER grant. The
            # closed seccomp profile denies link/other truncate syscalls and
            # permits only non-truncating read or exclusive-create open flags.
            access = (2 | 4 | 8 | 32 | 256 | 8192 | 16384) & handled
            path = PathBeneath(access, 3)
            if libc.syscall(445, ruleset, 1, ctypes.byref(path), 0):
                raise OSError("managed directory Landlock rule unavailable")
        if libc.syscall(446, ruleset, 0):
            raise OSError("owned Landlock restriction unavailable")
    finally:
        os.close(ruleset)
    checks = {}
    for label, flags in (
        ("outside_path_read_denied", os.O_RDONLY),
        ("outside_path_write_denied", os.O_WRONLY),
    ):
        try:
            opened = os.open(sys.argv[0], flags)
        except OSError as error:
            if error.errno != errno.EACCES:
                raise OSError("owned filesystem probe inconclusive") from None
            checks[label] = True
        else:
            os.close(opened)
            raise OSError("owned filesystem probe failed")
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise ValueError("owned worker identity differs")
    memory, cpu, file_bound = (
        packet["memory_bytes"],
        packet["cpu_seconds"],
        packet["file_size_bound"],
    )
    if (
        type(memory) is not int
        or not 64 * 1048576 <= memory <= 256 * 1048576
        or type(cpu) is not int
        or not 1 <= cpu <= 10
        or type(file_bound) is not int
        or not 8192 <= file_bound <= 139264
    ):
        raise ValueError("owned worker resource bounds invalid")
    descriptors = 6 if mode == "write" else 4
    for kind, maximum in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_AS, memory),
        (resource.RLIMIT_CPU, cpu),
        (resource.RLIMIT_NPROC, 1),
        (resource.RLIMIT_NOFILE, descriptors),
        (resource.RLIMIT_FSIZE, file_bound),
    ):
        resource.setrlimit(kind, (maximum, maximum))
    # Read back while prlimit/getrlimit is still available. The subsequent
    # immutable filter intentionally denies all resource-limit mutation/query
    # syscalls; it must not be broadened merely to serialize this receipt.
    limits = {
        "memory_bytes": list(resource.getrlimit(resource.RLIMIT_AS)),
        "cpu_seconds": list(resource.getrlimit(resource.RLIMIT_CPU)),
        "processes": list(resource.getrlimit(resource.RLIMIT_NPROC)),
        "descriptors": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "file_bytes": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
        "core_bytes": list(resource.getrlimit(resource.RLIMIT_CORE)),
    }
    expected_limits = {
        "memory_bytes": [memory] * 2,
        "cpu_seconds": [cpu] * 2,
        "processes": [1, 1],
        "descriptors": [descriptors] * 2,
        "file_bytes": [file_bound] * 2,
        "core_bytes": [0, 0],
    }
    if limits != expected_limits:
        raise OSError("owned resource limit readback differs")
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    try:
        os.ftruncate(1, file_bound * 2)
    except OSError as error:
        if error.errno != errno.EFBIG:
            raise OSError("owned file-size probe inconclusive") from None
        checks["file_size_ceiling_enforced"] = True
    else:
        raise OSError("owned file-size ceiling absent")

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    code = filter_code(mode)
    profile = filter_digest(mode)
    if packet["filter_digest"] != profile:
        raise ValueError("owned filter identity differs")
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
        raise OSError("owned seccomp unavailable")
    if libc.prctl(21, 0, 0, 0, 0) != 2 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError("owned restriction readback differs")
    for label, number, arguments in (
        ("new_socket_denied", 41, (2, 1, 0)),
        ("process_creation_denied", 57, ()),
        ("executable_launch_denied", 59, (ctypes.c_char_p(b"/never-executable"), None, None)),
    ):
        result = libc.syscall(number, *arguments)
        if label == "process_creation_denied" and result == 0:
            os._exit(126)
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            if label == "new_socket_denied" and result >= 0:
                os.close(result)
            raise OSError("owned syscall denial probe failed")
        checks[label] = True
    if mode == "http":
        nonblocking = ctypes.c_int(1)
        if libc.syscall(16, 3, FIONBIO, ctypes.byref(nonblocking)) != 0:
            raise OSError("owned preconnected socket nonblocking control unavailable")
        checks["preconnected_socket_nonblocking_control"] = True
        for socket_label, socket_number, socket_arguments in (
            ("wrong_socket_ioctl_descriptor_denied", 16, (0, FIONBIO, ctypes.byref(nonblocking))),
            ("wrong_socket_ioctl_request_denied", 16, (3, 0x541B, ctypes.byref(nonblocking))),
            ("socket_fcntl_denied", 72, (3, 3)),
            ("socket_connect_denied", 42, (3, None, 0)),
        ):
            if (
                libc.syscall(socket_number, *socket_arguments) != -1
                or ctypes.get_errno() != errno.EPERM
            ):
                raise OSError("owned socket restriction probe failed")
            checks[socket_label] = True
    allocation = mmap(None, memory * 2, 3, 0x22, -1, 0)
    if allocation != ctypes.c_void_p(-1).value or ctypes.get_errno() != errno.ENOMEM:
        if allocation != ctypes.c_void_p(-1).value:
            libc.munmap(allocation, memory * 2)
        raise OSError("owned memory ceiling probe failed")
    checks["memory_ceiling_enforced"] = True
    return {
        "landlock_abi": abi,
        "seccomp_mode": 2,
        "no_new_privileges": 1,
        "filter_digest": profile,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "environment_empty": not os.environ,
        "checks": checks,
        "filesystem_scope": "managed_directory" if mode == "write" else "no_new_paths",
        "network_scope": "denied" if mode == "write" else "one_preconnected_destination",
        "process_creation": "denied",
        "executable_launch": "denied",
        "limits": limits,
    }
