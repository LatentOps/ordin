"""Standalone vetted worker; explicit Linux mode adds kernel self-restriction."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from typing import Any

PROTOCOL = "ordin.vetted_synthetic_test.v1"
LINUX_PROTOCOL = "ordin.vetted_synthetic_test.linux.v1"
LINUX_FILTER_DIGEST = "39ba6d1343b819518f4aa0465b533a048e3b174de064abf36cc9f356e8d0f261"


def _isolate_linux(limits):
    """Restrict this single disposable worker only; never a parent/host policy.

    Landlock denies filesystem rights. A seccomp allowlist independently blocks
    opens, truncation/rename/mount, networking, executable/process creation,
    credential changes, ptrace and resource-limit widening. Only three pipe
    descriptors survive. This fixed ABI profile is Linux x86-64 only.
    """
    import ctypes
    import errno
    import os
    import resource
    import stat

    if sys.platform != "linux" or os.uname().machine != "x86_64" or sys.byteorder != "little":
        raise ValueError("unsupported Linux isolation ABI")
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("isolation requires a single-threaded disposable worker")
    for fd in range(3):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError("isolation requires pipe-only transport")
    descriptors = os.listdir("/proc/self/fd")
    if len(descriptors) > 256:
        raise ValueError("isolation descriptor budget")
    for name in descriptors:
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise OSError("isolation descriptor closure unverified") from None
                # The enumeration's own directory descriptor is closed.
    os.environ.clear()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS.
        raise OSError("isolation privilege restriction unavailable")
    abi = libc.syscall(444, None, 0, 1)  # Landlock version query only.
    if abi < 1:
        raise OSError("Landlock isolation unavailable")

    class LandlockRuleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    rules = LandlockRuleset((1 << 13) - 1)  # All ABI-1 filesystem rights; no allow rules.
    ruleset = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if ruleset < 0:
        raise OSError("Landlock ruleset unavailable")
    try:
        if libc.syscall(446, ruleset, 0):
            raise OSError("Landlock restriction unavailable")
    finally:
        os.close(ruleset)
    checks = {}
    # The selected worker itself is a known existing owned file. Probe access
    # only; an unexpected write-open is closed without modifying its bytes.
    for label, flags in (
        ("filesystem_read_denied", os.O_RDONLY),
        ("filesystem_write_denied", os.O_WRONLY),
    ):
        try:
            descriptor = os.open(sys.argv[0], flags)
        except OSError as error:
            if error.errno != errno.EACCES:
                raise OSError("Landlock enforcement probe inconclusive") from None
            checks[label] = True
        else:
            os.close(descriptor)
            raise OSError("Landlock enforcement probe failed")
    memory = limits["memory_mib"] * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"]))
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (3, 3))
    observed_limits = {
        "cpu_seconds": list(resource.getrlimit(resource.RLIMIT_CPU)),
        "memory_bytes": list(resource.getrlimit(resource.RLIMIT_AS)),
        "max_processes": list(resource.getrlimit(resource.RLIMIT_NPROC)),
        "max_descriptors": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
        "core_bytes": list(resource.getrlimit(resource.RLIMIT_CORE)),
    }

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]

    # x86-64 syscall numbers from the pinned Linux 5.15 syscall table. No path,
    # socket, process, exec, signal-to-other-process or resource-write syscall.
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
    # Permit only readback prctl operations, not privilege/filter mutation.
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
    profile_digest = hashlib.sha256(json.dumps(code, separators=(",", ":")).encode()).hexdigest()
    if profile_digest != LINUX_FILTER_DIGEST:
        raise ValueError("Linux isolation filter profile changed")
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
    libc.munmap.restype = ctypes.c_int
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0):  # PR_SET_SECCOMP/FILTER.
        raise OSError("seccomp isolation unavailable")
    seccomp = libc.prctl(21, 0, 0, 0, 0)
    privileges = libc.prctl(39, 0, 0, 0, 0)
    if seccomp != 2 or privileges != 1:
        raise OSError("kernel isolation readback mismatch")
    for label, number, args in (
        ("network_socket_denied", 41, (2, 1, 0)),
        ("process_fork_denied", 57, ()),
        (
            "executable_launch_denied",
            59,
            (ctypes.c_char_p((sys.argv[0] + "/never-executable").encode()), None, None),
        ),
    ):
        result = libc.syscall(number, *args)
        if label == "process_fork_denied" and result == 0:
            os._exit(126)  # A failed owned probe never creates a persistent child.
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            if label == "network_socket_denied" and result >= 0:
                os.close(result)
            raise OSError("seccomp enforcement probe failed")
        checks[label] = True
    allocated = mmap(None, memory * 2, 3, 0x22, -1, 0)
    if allocated != ctypes.c_void_p(-1).value or ctypes.get_errno() != errno.ENOMEM:
        if allocated != ctypes.c_void_p(-1).value:
            libc.munmap(allocated, memory * 2)
        raise OSError("memory ceiling enforcement probe failed")
    checks["memory_ceiling_enforced"] = True
    return {
        "backend": "linux-memory-only-v1",
        "landlock_abi": abi,
        "seccomp_mode": seccomp,
        "no_new_privileges": privileges,
        "filter_digest": profile_digest,
        "limits": observed_limits,
        "environment_empty": not os.environ,
        "pipe_only_transport": True,
        "filesystem_access": "denied",
        "network_access": "denied",
        "process_creation": "denied",
        "executable_launch": "denied",
        "checks": checks,
    }


def vet_program(source):
    if not isinstance(source, str) or not 1 <= len(source.encode("utf-8")) <= 4096:
        raise ValueError("unsupported synthetic program")
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError):
        raise ValueError("unsupported synthetic program syntax") from None
    nodes = list(ast.walk(tree))
    if len(nodes) > 64 or len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("unsupported synthetic program")
    function = tree.body[0]
    if (
        function.name != "within_root"
        or function.decorator_list
        or function.returns
        or function.type_comment
        or getattr(function, "type_params", None)
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
        or function.args.posonlyargs
        or function.args.kwonlyargs
        or function.args.vararg
        or function.args.kwarg
        or function.args.defaults
        or function.args.kw_defaults
        or [arg.arg for arg in function.args.args] != ["path", "root"]
        or any(arg.annotation for arg in function.args.args)
    ):
        raise ValueError("unsupported synthetic program")

    def expression(node, depth=0):
        if depth > 8:
            raise ValueError("synthetic expression limit")
        if isinstance(node, ast.Name) and node.id in {"path", "root"}:
            return
        if isinstance(node, ast.Constant) and type(node.value) is str and node.value in {"", "/"}:
            return
        if (
            isinstance(node, ast.BoolOp)
            and isinstance(node.op, (ast.And, ast.Or))
            and 2 <= len(node.values) <= 4
        ):
            for child in node.values:
                expression(child, depth + 1)
            return
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        ):
            expression(node.left, depth + 1)
            expression(node.comparators[0], depth + 1)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            expression(node.left, depth + 1)
            expression(node.right, depth + 1)
            return
        if (
            isinstance(node, ast.Call)
            and not node.keywords
            and len(node.args) == 1
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"startswith", "rstrip"}
        ):
            expression(node.func.value, depth + 1)
            expression(node.args[0], depth + 1)
            return
        raise ValueError("synthetic program contains an unvetted operation")

    expression(function.body[0].value)
    return ast.unparse(tree) + "\n"


def expected_path_result(path, root):
    # Independent lexical property. Physical paths/aliases are outside this test.
    return path == root or path.startswith(root + "/")


def execute_request(packet, *, isolated=False):
    if isolated and sys.argv[1:] != ["--linux-isolated"]:
        raise ValueError("kernel isolation is restricted to the disposable worker entrypoint")
    expected_fields = {
        "protocol",
        "request_digest",
        "source_digest",
        "suite_digest",
        "runtime_digest",
        "program",
        "cases",
        "limits",
    }
    if (
        not isinstance(packet, dict)
        or set(packet) != expected_fields
        or packet["protocol"] != (LINUX_PROTOCOL if isolated else PROTOCOL)
    ):
        raise ValueError("unsupported worker request")
    material = {key: value for key, value in packet.items() if key != "request_digest"}
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    if hashlib.sha256(encoded).hexdigest() != packet["request_digest"]:
        raise ValueError("worker request binding changed")
    limits = packet["limits"]
    bounds = {
        "timeout_ms": (100, 30000),
        "cpu_seconds": (1, 30),
        "memory_mib": (32, 1024),
        "max_processes": (1, 4),
        "max_output_bytes": (1024, 65536),
    }
    if (
        not isinstance(limits, dict)
        or set(limits) != set(bounds)
        or any(
            type(limits[key]) is not int or not low <= limits[key] <= high
            for key, (low, high) in bounds.items()
        )
    ):
        raise ValueError("worker resource contract malformed")
    program = vet_program(packet["program"])
    cases = packet["cases"]
    if not isinstance(cases, list) or not 2 <= len(cases) <= 32:
        raise ValueError("worker case limit")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"case_id", "path", "root"}:
            raise ValueError("worker case malformed")
        if any(type(case[key]) is not str or not 1 <= len(case[key]) <= 256 for key in case):
            raise ValueError("worker case malformed")
    isolation = _isolate_linux(limits) if isolated else None
    namespace: dict[str, Any] = {"__builtins__": {}}
    exec(compile(program, "<vetted-synthetic-predicate>", "exec"), namespace)
    results = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"case_id", "path", "root"}:
            raise ValueError("worker case malformed")
        if any(type(case[key]) is not str or not 1 <= len(case[key]) <= 256 for key in case):
            raise ValueError("worker case malformed")
        actual = namespace["within_root"](case["path"], case["root"])
        if type(actual) is not bool:
            raise ValueError("worker prediction must be boolean")
        results.append({"case_id": case["case_id"], "actual": actual})
    result = {
        "protocol": LINUX_PROTOCOL if isolated else PROTOCOL,
        "request_digest": packet["request_digest"],
        "source_digest": packet["source_digest"],
        "suite_digest": packet["suite_digest"],
        "results": results,
    }
    if isolated:
        result["isolation"] = isolation
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("input limit")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate input")
                result[key] = value
            return result

        def reject(_):
            raise ValueError("nonfinite input")

        packet = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
        if sys.argv[1:] not in ([], ["--linux-isolated"]):
            raise ValueError("unsupported worker mode")
        result = execute_request(packet, isolated=sys.argv[1:] == ["--linux-isolated"])
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"error":"vetted_test_refused"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
