"""Pure bootstrap ordering; no worker import, isolation, or native execution."""

import ast
import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest


def run_bootstrap(mode="pytest", *, damage=None):
    source = Path(__file__).resolve().parents[1] / "ordin/swarm/_managed_worker.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    original_isolate = functions["isolate"]
    # Execute the actual validated pre-boundary phase only. Native operations
    # after this point are represented by a marker, never called by this test.
    end = next(
        index
        for index, node in enumerate(original_isolate.body)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "libc" for target in node.targets)
    )
    imports = [
        alias.name
        for node in ast.walk(ast.Module(body=original_isolate.body[:end], type_ignores=[]))
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    assert imports == ["zlib"]
    preload_line = next(
        node.lineno
        for node in ast.walk(original_isolate)
        if isinstance(node, ast.Import) and node.names[0].name == "zlib"
    )
    assert preload_line < min(
        node.lineno
        for node in ast.walk(original_isolate)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"unshare", "chroot"}
    )
    prefix = ast.FunctionDef(
        name="validated_preload",
        args=original_isolate.args,
        body=original_isolate.body[:end],
        decorator_list=[],
    )
    events: list[object] = []
    packet = {
        "protocol": "ordin.protected_python.v1",
        "mode": mode,
        "nonce": "original-nonce",
        "binding": "original-binding",
        "jail": "/private-jail",
        "ipc_fd": 3,
        "uid": 65534,
        "gid": 65534,
        "limits": {
            "timeout_ms": 1000,
            "cpu_seconds": 1,
            "memory_mib": 128,
            "output_bytes": 8192,
            "scratch_bytes": 1048576,
            "scratch_inodes": 256,
            "maximum_calls": 1,
        },
        "program": "",
    }
    if mode == "pytest":
        packet["test"] = {
            "project_root": "/untrusted-project",
            "snapshot": "/private-snapshot",
            "snapshot_digest": "a" * 64,
            "runtime_root": "/pinned-runtime",
            "runtime_digest": "b" * 64,
            "stdlib_virtual": "/trusted-stdlib",
            "selectors": ["test_sample.py"],
        }
    if damage is not None:
        damage(packet)
    fake_sys = SimpleNamespace(
        platform="linux",
        path=["/trusted-stdlib", "/trusted-stdlib/lib-dynload"],
        path_importer_cache={},
    )

    def file_status(descriptor):
        return SimpleNamespace(
            st_mode="fifo" if descriptor == 0 else "socket" if descriptor == 3 else "file",
            st_nlink=0,
            st_dev=1,
            st_ino=1,
        )

    fake_os = SimpleNamespace(
        uname=lambda: SimpleNamespace(machine="x86_64"),
        geteuid=lambda: 0,
        listdir=lambda path: ["one"] if path == "/proc/self/task" else ["0", "1", "2", "3"],
        fstat=file_status,
        environ={},
        O_ACCMODE=3,
        O_WRONLY=1,
        close=lambda descriptor: events.append(("close", descriptor)),
        chdir=lambda path: events.append(("chdir", path)),
    )

    def pytest_main(arguments):
        assert "ack" in events and "isolated" in events
        assert fake_sys.path[-1] == "/untrusted-project"
        events.append("tests")
        return 0

    def trusted_import(name, *args, **kwargs):
        assert name in {"zlib", "pytest"}, "bootstrap attempted general module discovery"
        if name == "zlib":
            assert not events and fake_sys.path == [
                "/trusted-stdlib",
                "/trusted-stdlib/lib-dynload",
            ]
        else:
            assert "isolated" in events and "ack" in events
        events.append(("import", name))
        return SimpleNamespace(main=pytest_main)

    def read_frame(descriptor, maximum):
        if descriptor == 0:
            return packet
        events.append("ack")
        return {"protocol": packet["protocol"], "phase": "start", "binding": packet["binding"]}

    namespace = {
        "__builtins__": dict(vars(builtins), __import__=trusted_import),
        "sys": fake_sys,
        "os": fake_os,
        "stat": SimpleNamespace(
            S_ISFIFO=lambda mode: mode == "fifo",
            S_ISREG=lambda mode: mode == "file",
            S_ISSOCK=lambda mode: mode == "socket",
        ),
        "fcntl": SimpleNamespace(F_GETFL=3, fcntl=lambda *args: 1),
        "PROTOCOL": packet["protocol"],
        "read_frame": read_frame,
        "send_frame": lambda descriptor, value, maximum: events.append(value["phase"]),
        "BrokerClient": object,
        "json": None,
        "math": None,
        "io": None,
        "pathlib": SimpleNamespace(Path=Path),
    }
    module = ast.fix_missing_locations(
        ast.Module(body=[prefix, functions["main"]], type_ignores=[])
    )
    exec(compile(module, str(source), "exec"), namespace)

    def isolate(packet):
        namespace["validated_preload"](packet)
        events.append("isolated")
        return {"original": "isolation-marker"}

    namespace["isolate"] = isolate
    return namespace["main"](), events


def test_fixed_stdlib_preload_precedes_isolation_project_paths_and_acknowledged_tests():
    result, events = run_bootstrap()
    assert result == 0
    assert events == [
        ("import", "zlib"),
        "isolated",
        "ready",
        "ack",
        ("close", 0),
        ("close", 3),
        ("chdir", "/untrusted-project"),
        ("import", "pytest"),
        "tests",
    ]


def test_agent_mode_does_not_preload_pytest_runtime_modules():
    result, events = run_bootstrap("agent")
    assert result == 0
    assert events == ["isolated", "ready", "ack", ("close", 0)]


@pytest.mark.parametrize(
    "damage",
    [
        lambda packet: packet.update(extra_module="project_zlib"),
        lambda packet: packet["test"].update(extra_module="project_zlib"),
        lambda packet: packet["test"].update(project_root="relative-project"),
        lambda packet: packet.update(uid=0),
        lambda packet: packet["limits"].update(timeout_ms=0),
    ],
)
def test_invalid_bootstrap_fails_before_any_privileged_extension_import(damage):
    result, events = run_bootstrap(damage=damage)
    assert result == 2
    assert events == ["unsupported"]
