"""Explicit private managed-host deployment and authenticated operator commands."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
from uuid import uuid4

from ordin.assurance._files import read_scoped_file, relative_parts
from ordin.schema import validate_named_schema

from .host_pki import _new_file, initialize_private_profile
from .host_profiles import (
    HOST_TOOL_DATA_BYTES,
    ToolHostProfile,
    check_private_directory,
    load_host_profile,
)
from .sdk import bounded_json


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("explicit absolute local path required")
    return path


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate configuration field")
        value[key] = item
    return value


def _document(path: Path) -> dict:
    raw = read_scoped_file(path.parent, path.name, maximum=65536, private=False)
    value = bounded_json(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique))
    if type(value) is not dict:
        raise ValueError("operator profile document required")
    return value


def _inputs(values, names, *, maximum, text):
    captured = {}
    for specification in values:
        name, separator, source = specification.partition("=")
        if not separator or name not in names or name in captured:
            raise ValueError("explicit unique configured input required")
        selected = _absolute(source)
        raw = read_scoped_file(selected.parent, selected.name, maximum=maximum, private=False)
        if text:
            from .host_runtime import _text

            _text(raw.decode("utf-8"))
        captured[name] = raw
    return captured


def initialize(
    directory: Path, document: dict, *, inputs=(), private_files=(), openssl=None, with_tests=False
):
    """Seed only a new dedicated workspace; never chown caller source data."""
    from .host_authority import initialize_host_authority_files

    profile = ToolHostProfile.from_dict(document, configuration_root=directory)
    if sys.platform != "linux" or directory.exists() or directory.is_symlink():
        raise ValueError("new private Linux installation required")
    if type(with_tests) is not bool or bool(profile.test_routes) is not with_tests:
        raise ValueError("fixed test staging requires explicit --with-tests and configured routes")
    from ordin.swarm.owned_tools import LinuxOwnedToolsBackend

    seeds = _inputs(
        inputs, {item.name for item in profile.files}, maximum=HOST_TOOL_DATA_BYTES, text=True
    )
    required = {name for actor in profile.actors for name in actor.read_files}
    required.update(
        selector.split("::", 1)[0] for route in profile.test_routes for selector in route.selectors
    )
    if not required <= set(seeds):
        raise ValueError("each configured readable file requires an explicit UTF-8 input")
    material = {
        name
        for route in profile.http_routes
        for name in (route.ca_file, route.credential_file)
        if name is not None
    }
    if any(
        relative_parts(name)[0]
        in {"pki", "state", "workspace", "clients", "profile.json", "assurance.json"}
        for name in material
    ):
        raise ValueError("private route material collides with managed installation files")
    copies = _inputs(private_files, material, maximum=16384, text=False)
    if set(copies) != material:
        raise ValueError("every configured private route file requires an explicit source")
    initialize_private_profile(directory, document, openssl_executable=openssl)
    # The backend's closed worker identity is chosen by its original factory.
    # Only objects created by this call are changed; partial installs are kept.
    uid, gid = LinuxOwnedToolsBackend.worker_identity()
    for name, raw in seeds.items():
        target = profile.workspace / name
        _new_file(target, raw)
        os.chown(target, uid, gid, follow_symlinks=False)
    os.chown(profile.workspace, uid, gid, follow_symlinks=False)
    for name, raw in copies.items():
        parts = relative_parts(name)
        parent = directory
        for part in parts[:-1]:
            parent /= part
            if not parent.exists():
                parent.mkdir(mode=0o700)
            check_private_directory(parent)
        _new_file(parent / parts[-1], raw)
    if with_tests:
        from ordin.swarm.confined_tests import build_python_runtime_catalog

        runtime = directory / "state" / "test-runtime"
        runtime.mkdir(mode=0o700)
        build_python_runtime_catalog(runtime, operator=object())
    loaded = load_host_profile(directory)
    initialize_host_authority_files(loaded, operator=object())
    return {
        "status": "initialized",
        "profile_digest": loaded.digest,
        "workspace": str(loaded.workspace),
        "fresh_private_pki": True,
        "scope_start_required": True,
        "execution_authority": False,
    }


def _rpc(connection, method, parameters=None):
    from .host_service import request

    value = request(
        connection,
        {
            "jsonrpc": "2.0",
            "id": uuid4().hex,
            "method": method,
            **({"params": parameters} if parameters is not None else {}),
        },
    )
    if type(value) is not dict or "error" in value or "result" not in value:
        raise ValueError("authenticated managed request did not complete")
    if type(value["result"]) is not dict:
        raise ValueError("bounded managed object result required")
    return value["result"]


def _initialize_connection(connection):
    from .host_service import request

    _rpc(
        connection,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "ordin-swarm-host-operator", "version": "1"},
        },
    )
    request(connection, {"jsonrpc": "2.0", "method": "notifications/initialized"})


def doctor(directory: Path, *, live=False, actor="operator"):
    profile = load_host_profile(directory)
    check_private_directory(directory)
    from .host_pki import PrivateHostPKI

    PrivateHostPKI(profile).require_unchanged()
    from ordin.swarm.budget_store import SQLiteBudgetStore
    from ordin.swarm.coordinator_store import SQLiteCoordinatorStore

    check_private_directory(directory / "state")
    SQLiteBudgetStore(directory / "state" / "budget.sqlite", create=False)
    SQLiteCoordinatorStore(directory / "state" / "coordinator.sqlite", create=False)
    if profile.test_routes:
        from .host_authority import host_test_routes

        host_test_routes(profile, operator=object())
    result = {
        "status": "configuration_valid",
        "profile_digest": profile.digest,
        "supported_platform": sys.platform == "linux",
        "online_verified": False,
        "execution_authority": False,
    }
    if live:
        from .host_service import connect

        _selected_actor(profile, actor)
        with connect(directory / "clients" / actor) as connection:
            _initialize_connection(connection)
            current = _rpc(connection, "ordin/status")
        if (
            validate_named_schema("swarm_tool_host_status", current)
            or current.get("profile_digest") != profile.digest
            or current.get("actor") != (None if actor == "operator" else actor)
        ):
            raise ValueError("live managed profile or original actor differs")
        result.update(status="live_verified", online_verified=current["online"], host=current)
    return result


def _selected_actor(profile, actor):
    if actor != "operator":
        profile.actor(actor)


def client_configuration(directory: Path, actor: str, *, python: Path):
    profile = load_host_profile(directory)
    _selected_actor(profile, actor)
    client = directory / "clients" / actor
    document = _document(client / "client.json")
    if (
        validate_named_schema("swarm_tool_host_client", document)
        or document["profile_digest"] != profile.digest
        or document["actor_id"] != actor
    ):
        raise ValueError("managed client bundle differs from selected profile")
    if not python.is_absolute() or not python.is_file():
        raise ValueError("explicit installed Python executable required")
    return {
        "mcpServers": {
            "ordin-" + actor: {
                "command": str(python),
                "args": [
                    "-m",
                    "ordin_swarm.host_cli",
                    "connect",
                    "--client-directory",
                    str(client),
                ],
            }
        }
    }


def _private_output(path: Path, value: dict):
    check_private_directory(path.parent)
    raw = (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    _new_file(path, raw)
    return {
        "status": "private_output_written",
        "path": str(path),
        "bytes": len(raw),
        "execution_authority": False,
    }


def _operator_success(action, result):
    if result.get("status") != "completed":
        return False
    if action == "fulfill":
        fulfilled = result.get("data", {}).get("fulfillment")
        return type(fulfilled) is dict and fulfilled.get("status") == "completed"
    return True


def _public_fulfillment(result):
    """Ordinary operator logs omit tool bodies and untrusted test diagnostics."""
    value = dict(result)
    fulfilled = result.get("data", {}).get("fulfillment")
    fields = {
        "schema_version",
        "status",
        "reason_codes",
        "forwarded",
        "physical_enforcement",
        "execution_authority",
    }
    value["data"] = (
        {
            "fulfillment": {
                **{key: item for key, item in fulfilled.items() if key in fields},
                "data": {},
            }
        }
        if type(fulfilled) is dict
        else {}
    )
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ordin-swarm-host")
    commands = parser.add_subparsers(dest="operation", required=True)
    init = commands.add_parser("init", help="create a new private Linux host with fresh PKI")
    init.add_argument("--directory", type=_absolute, required=True)
    init.add_argument("--profile", type=_absolute, required=True)
    init.add_argument("--input", action="append", default=[], metavar="NAME=/ABSOLUTE/UTF8_FILE")
    init.add_argument("--private-file", action="append", default=[], metavar="NAME=/ABSOLUTE/FILE")
    init.add_argument("--openssl", type=_absolute)
    init.add_argument("--with-tests", action="store_true")
    serve = commands.add_parser("serve", help="run one shared loopback mTLS daemon")
    serve.add_argument("--directory", type=_absolute, required=True)
    serve.add_argument("--port", type=int, default=9443)
    serve.add_argument("--policy-epoch", type=int, required=True)
    mode = serve.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initialize-scope", action="store_true")
    mode.add_argument("--takeover", action="store_true")
    inspect = commands.add_parser("doctor")
    inspect.add_argument("--directory", type=_absolute, required=True)
    inspect.add_argument("--live", action="store_true")
    inspect.add_argument("--actor", default="operator")
    config = commands.add_parser("client-config")
    config.add_argument("--directory", type=_absolute, required=True)
    config.add_argument("--actor", required=True)
    config.add_argument("--python", type=_absolute, default=Path(sys.executable))
    config.add_argument("--output", type=_absolute, required=True)
    bridge = commands.add_parser("connect")
    bridge.add_argument("--client-directory", type=_absolute, required=True)
    evaluation = commands.add_parser(
        "evaluate", help="run the fixed offline two-agent effect evaluation"
    )
    evaluation.add_argument("--directory", type=_absolute, required=True)
    evaluation.add_argument("--output", type=_absolute, required=True)
    evaluation.add_argument("--openssl", type=_absolute)
    evaluation.add_argument("--with-tests", action="store_true")
    evaluation.add_argument("--protected-agent", action="store_true")
    operator = commands.add_parser("operator")
    operator.add_argument("--directory", type=_absolute, required=True)
    actions = operator.add_subparsers(dest="action", required=True)
    queue = actions.add_parser("queue")
    queue.add_argument("--offset", type=int, default=0)
    queue.add_argument("--limit", type=int, default=8)
    show = actions.add_parser("show")
    show.add_argument("--request-ref", required=True)
    show.add_argument("--include-content", action="store_true")
    show.add_argument("--preview", type=_absolute)
    for name in ("approve", "deny", "fulfill"):
        command = actions.add_parser(name)
        command.add_argument("--request-ref", required=True)
        command.add_argument("--expected-binding", required=True)
        if name != "fulfill":
            command.add_argument("--idempotency-key", required=True)
        else:
            command.add_argument("--private-result", type=_absolute)
    actions.add_parser("stop")
    args = parser.parse_args(argv)
    try:
        exit_code = 0
        if args.operation == "init":
            result = initialize(
                args.directory,
                _document(args.profile),
                inputs=args.input,
                private_files=args.private_file,
                openssl=args.openssl,
                with_tests=args.with_tests,
            )
        elif args.operation == "doctor":
            result = doctor(args.directory, live=args.live, actor=args.actor)
            if not result["supported_platform"] or args.live and not result["online_verified"]:
                exit_code = 2
        elif args.operation == "client-config":
            result = _private_output(
                args.output, client_configuration(args.directory, args.actor, python=args.python)
            )
        elif args.operation == "evaluate":
            from .host_evaluation import run_evaluation

            evaluated = run_evaluation(
                args.directory,
                openssl=args.openssl,
                with_tests=args.with_tests,
                protected=args.protected_agent,
            )
            result = _private_output(args.output, evaluated)
            result["passed"] = evaluated["passed"]
        elif args.operation == "connect":
            from .host_service import bridge_stdio

            return bridge_stdio(args.client_directory, sys.stdin.buffer, sys.stdout.buffer)
        elif args.operation == "serve":
            from .host_runtime import ManagedToolHost
            from .host_service import ManagedHostServer

            capability = object()
            host = ManagedToolHost(
                load_host_profile(args.directory),
                operator=capability,
                policy_epoch=args.policy_epoch,
                initialize_scope=args.initialize_scope,
                takeover=args.takeover,
            )
            try:
                server = ManagedHostServer(host, operator=capability, port=args.port)
                previous = {}
                for name in ("SIGINT", "SIGTERM"):
                    number = getattr(signal, name, None)
                    if number is not None:
                        previous[number] = signal.signal(
                            number, lambda *_: host.shutdown_requested.set()
                        )
                try:
                    print(
                        json.dumps(
                            {
                                "status": "listening",
                                "host": "127.0.0.1",
                                "port": server.port,
                                "profile_digest": host.profile.digest,
                                "execution_authority": False,
                            }
                        ),
                        flush=True,
                    )
                    return server.run()
                finally:
                    for number, handler in previous.items():
                        signal.signal(number, handler)
            finally:
                host.close()
        else:
            from .host_service import connect

            profile = load_host_profile(args.directory)
            parameters = {}
            operation = args.action
            if operation == "queue":
                parameters = {"offset": args.offset, "limit": args.limit}
            elif operation == "show":
                if (
                    args.include_content
                    and args.preview is None
                    or args.preview is not None
                    and not args.include_content
                ):
                    raise ValueError("content preview requires an explicit private output file")
                parameters = {
                    "request_ref": args.request_ref,
                    "include_content": args.include_content,
                }
            elif operation in {"approve", "deny", "fulfill"}:
                parameters = {
                    "request_ref": args.request_ref,
                    "expected_binding": args.expected_binding,
                }
                if operation != "fulfill":
                    parameters.update(choice=operation, idempotency_key=args.idempotency_key)
                    operation = "resolve"
            elif operation == "stop":
                operation = "shutdown"
            with connect(profile.configuration_root / "clients" / "operator") as connection:
                _initialize_connection(connection)
                result = _rpc(connection, "ordin/operator/" + operation, parameters)
            if validate_named_schema("swarm_tool_host_result", result):
                raise ValueError("invalid authenticated operator outcome")
            if not _operator_success(args.action, result):
                exit_code = 2
            if args.action == "show" and args.include_content:
                result = _private_output(args.preview, result)
            elif args.action == "fulfill":
                result = (
                    _private_output(args.private_result, result)
                    if args.private_result is not None
                    else _public_fulfillment(result)
                )
        print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False), flush=True)
        return 1 if args.operation == "evaluate" and not result["passed"] else exit_code
    except (ValueError, OSError, RuntimeError, UnicodeError):
        # Never emit raw exceptions: paths, TLS errors and proposals can contain
        # secrets. An unknown response is never a reason to replay an effect.
        print(
            json.dumps(
                {
                    "status": "unavailable",
                    "reason_code": "host.command_failed",
                    "execution_authority": False,
                }
            ),
            file=sys.stderr,
            flush=True,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
