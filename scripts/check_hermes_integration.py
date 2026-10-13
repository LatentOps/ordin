"""Exercise the installed hook through hash-pinned Hermes production code.

Loads the real shell launcher/parser and AST-selected, unmodified production
guard/approval functions. Profile, secret environment, ACP and approval UI are
explicit fixtures. This is a host contract test, not a live model/sandbox test.
"""

from __future__ import annotations

import argparse
import ast
from contextlib import suppress
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import types
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ordin.hermes import HERMES_REVISION, HERMES_VERSION
from ordin.setup import TARGETS, apply, config_content


SOURCES = {
    "agent/shell_hooks.py": "92b55fbff1be18ea047b748afe77555ce57a64fcba6cbc378ddd6a3b7dc7481b",
    "hermes_cli/_subprocess_compat.py": "4d036c56de8065099f4b82a50fde9095c43dab7e851e0e3a3fe4cd5c143a212e",
    "hermes_cli/plugins.py": "f5a1c27a22025984bbf956b58154ce23914592307bd945d7a1c0167cc443d771",
    "model_tools.py": "872ca571c17379c8df19c0bcf639919bb0cb3a2706efc08e4dc6a1f3d8789662",
    "tools/registry.py": "4a05aae5b4dd40bf9a104d23582d4363326ad7ce3fdac1ac249e0af04334d909",
}


def _download_source(url: str) -> bytes:
    """Bounded retries for transient transport errors; every byte is still hash-checked."""
    request = Request(url, headers={"User-Agent": "ordin-hermes-contract/1"})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=30) as response:
                return response.read(5_000_001)
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable source download retry")


def fixture(name: str, **attributes: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    sys.modules[name] = module
    return module


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_functions(module: types.ModuleType, path: Path, names: set[str]) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    assert {node.name for node in selected} == names
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    tree = ast.fix_missing_locations(ast.Module(body=[future, *selected], type_ignores=[]))
    exec(compile(tree, str(path), "exec"), module.__dict__)


def load_registry_normalizer(module: types.ModuleType, path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "_MAX_TOOL_ERROR_CHARS",
                    "_MAX_LOGGED_ERROR_CHARS",
                    "_TOOL_ERROR_TRUNCATION_MARKER",
                }:
                    module.__dict__[target.id] = ast.literal_eval(node.value)
    load_functions(module, path, {"_bound_json_error_result", "_bound_error_text", "tool_error"})
    registry = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ToolRegistry"
    )
    method = next(
        node
        for node in registry.body
        if isinstance(node, ast.FunctionDef) and node.name == "_normalize_handler_result"
    )
    # Keep the method and decorators unchanged; other registry services are not used.
    registry.body = [method]
    selected = ast.fix_missing_locations(ast.Module(body=[registry], type_ignores=[]))
    exec(compile(selected, str(path), "exec"), module.__dict__)


def run(source: Path | None = None) -> dict[str, Any]:
    checks = []

    def check(name: str, passed: bool) -> None:
        checks.append({"id": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)

    with tempfile.TemporaryDirectory(prefix="ordin-hermes-contract-") as directory:
        root = Path(directory).resolve()
        upstream = root / "upstream"
        for relative, expected in SOURCES.items():
            if source is None:
                url = f"https://raw.githubusercontent.com/NousResearch/hermes-agent/{HERMES_REVISION}/{relative}"
                raw = _download_source(url)
            else:
                raw = (source / relative).read_bytes()
            check(
                "pinned_source:" + relative,
                len(raw) <= 5_000_000 and hashlib.sha256(raw).hexdigest() == expected,
            )
            path = upstream / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        profile = {"name": "default"}
        approval = {"approved": False, "error": False, "count": 0}
        contributions: list[Any] = []
        for name in ("agent", "hermes_cli", "tools", "tools.environments", "acp_adapter"):
            fixture(name).__path__ = []
        fixture("hermes_constants", get_hermes_home=lambda: root)
        fixture("utils", atomic_json_write=lambda *a, **kw: None)
        fixture("hermes_cli.profiles", get_active_profile_name=lambda: profile["name"])
        fixture("agent.secret_scope", is_multiplex_active=lambda: False)
        fixture(
            "tools.environments.local",
            build_subprocess_env=lambda **kw: {
                key: value for key, value in os.environ.items() if not key.startswith("ORDIN_")
            },
        )
        fixture("acp_adapter.edit_approval", maybe_require_edit_approval=lambda *a: None)

        def request_approval(*args: Any, **kwargs: Any) -> dict[str, Any]:
            approval["count"] += 1
            if approval["error"]:
                raise RuntimeError("fixture approval failure")
            return {"approved": approval["approved"]}

        fixture("tools.approval", request_tool_approval=request_approval)
        fixture(
            "tools.approval_context",
            set_current_observability_context=lambda **kw: None,
            reset_current_observability_context=lambda *a: None,
        )
        load_module("hermes_cli._subprocess_compat", upstream / "hermes_cli/_subprocess_compat.py")
        shell = load_module("agent.shell_hooks", upstream / "agent/shell_hooks.py")
        settings = {
            "integration": "hermes",
            "config": TARGETS["hermes"],
            "python": sys.executable,
            "state": True,
            "audit": True,
            "observations": True,
            "shell": "bash",
            "server_id": None,
            "command": [],
            "upstream": None,
            "port": 8766,
            "semantics": None,
            "inventory": None,
            "contract_lock": None,
        }
        home = root / "profile with spaces"
        home.mkdir()
        apply(settings, home)
        hooks = json.loads(config_content(settings, home))["hooks"]
        specs = {
            event: shell.ShellHookSpec(event=event, **entries[0])
            for event, entries in hooks.items()
        }
        posts: list[dict[str, Any]] = []

        def invoke_lifecycle(event: str, **kwargs: Any) -> list[Any]:
            if event == "post_tool_call":
                result = shell.run_once(specs[event], kwargs)
                posts.append(result)
                return [result["parsed"]]
            return (
                [shell._make_callback(specs[event])(**kwargs), *contributions]
                if event in specs
                else []
            )

        fixture(
            "hermes_cli.lifecycle",
            invoke_hook=invoke_lifecycle,
            has_hook=lambda event: event in specs,
        )
        plugins = fixture(
            "hermes_cli.plugins",
            dataclass=dataclass,
            Optional=Optional,
            Any=Any,
            suppress=suppress,
            _thread_tool_whitelist=threading.local(),
        )
        # Take the upstream event allowlists verbatim, as well as production functions.
        tree = ast.parse((upstream / "hermes_cli/plugins.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id in {"VALID_HOOKS", "SHELL_UNSUPPORTED_HOOKS"}
            ):
                plugins.__dict__[node.target.id] = ast.literal_eval(node.value)
            elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "SHELL_UNSUPPORTED_HOOKS"
                for target in node.targets
            ):
                plugins.SHELL_UNSUPPORTED_HOOKS = ast.literal_eval(node.value)
        parsed = shell._parse_hooks_block(hooks)
        check(
            "native_config_parser",
            len(parsed) == len(specs)
            and all(spec.fail_closed == (spec.event == "pre_tool_call") for spec in parsed),
        )
        load_functions(
            plugins,
            upstream / "hermes_cli/plugins.py",
            {
                "_PreToolCallDirective",
                "_get_pre_tool_call_directive_details",
                "_resolve_block_from_details",
                "_dispatch_pre_tool_call_hooks",
            },
        )
        guards = fixture(
            "ordin_hermes_host_guards",
            dataclass=dataclass,
            asdict=asdict,
            Any=Any,
            Optional=Optional,
            logger=logging.getLogger("hermes-contract"),
            tool_error=lambda message: message,
            _post_tool_call_hook_suppressed=types.SimpleNamespace(get=lambda: False),
        )
        load_functions(
            guards,
            upstream / "model_tools.py",
            {"_CallIds", "_pre_dispatch_guards", "_emit_post_tool_call_hook"},
        )
        normalization = fixture(
            "ordin_hermes_result_normalization",
            json=json,
            logger=logging.getLogger("hermes-contract"),
        )
        load_registry_normalizer(normalization, upstream / "tools/registry.py")
        executions = []

        def dispatch(tool: str, arguments: dict[str, Any], call: str) -> Any:
            ids = guards._CallIds(
                session_id="conversation", tool_call_id=call, task_id="task", turn_id="turn"
            )
            effective, blocked = guards._pre_dispatch_guards(tool, arguments, False, ids, [])
            if blocked is None:
                executions.append(
                    (tool, effective)
                )  # Harmless fixture tool; no shell/file execution.
            return effective, blocked

        check(
            "allow_reaches_dispatch",
            dispatch("terminal", {"command": "git status"}, "allow")[1] is None
            and len(executions) == 1,
        )
        before = len(executions)
        check(
            "deny_stops_dispatch",
            dispatch("terminal", {"command": "rm -rf /"}, "deny")[1] is not None
            and len(executions) == before,
        )
        check(
            "ask_requires_human",
            dispatch("unknown_tool", {}, "ask-denied")[1] is not None and approval["count"] == 1,
        )
        approval["approved"] = True
        check(
            "human_approval_reaches_dispatch",
            dispatch("unknown_tool", {}, "ask-approved")[1] is None and approval["count"] == 2,
        )
        approval["error"] = True
        check(
            "approval_error_stops_dispatch",
            dispatch("unknown_tool", {}, "ask-error")[1] is not None,
        )
        approval["error"] = False
        for call, result in (
            ("plain-result", "private plain result"),
            (
                "multimodal-result",
                {
                    "_multimodal": True,
                    "content": [{"type": "text", "text": "private multimodal result"}],
                },
            ),
        ):
            check(call + "_review_allowed", dispatch("unknown_tool", {}, call)[1] is None)
            normalized = normalization.ToolRegistry._normalize_handler_result(
                "unknown_tool", result
            )
            guards._emit_post_tool_call_hook(
                function_name="unknown_tool",
                function_args={},
                result=normalized,
                session_id="conversation",
                tool_call_id=call,
                status="ok",
            )
            check(call + "_production_post_callback", posts[-1]["returncode"] == 0)
        check(
            "missing_call_id_blocks",
            dispatch("terminal", {"command": "git status"}, "")[1] is not None,
        )
        profile["name"] = "other"
        check(
            "profile_isolation", dispatch("terminal", {"command": "git status"}, "allow")[1] is None
        )
        profile["name"] = "default"
        check(
            "duplicate_review_blocks",
            dispatch("terminal", {"command": "git status"}, "allow")[1] is not None,
        )
        contributions.append({"action": "modify", "args": {"command": "echo changed"}})
        effective, blocked = dispatch("terminal", {"command": "git status"}, "rewrite")
        check(
            "host_rewrite_coverage_limit",
            blocked is None and effective["command"] == "echo changed",
        )
        contributions.clear()
        observed = shell.run_once(
            specs["post_tool_call"],
            {
                "tool_name": "terminal",
                "args": effective,
                "session_id": "conversation",
                "tool_call_id": "rewrite",
                "status": "ok",
                "result": '{"exit_code":0}',
            },
        )
        check("rewritten_post_cannot_attach", observed["returncode"] == 2)
        for name, code in (
            ("crash", "raise RuntimeError('fixture crash')"),
            ("malformed_stdout", "print('broken-json')"),
            ("timeout", "import time; time.sleep(10)"),
        ):
            script = root / (name + ".py")
            script.write_text(code, encoding="utf-8")
            command = (
                subprocess.list2cmdline([sys.executable, str(script)])
                if os.name == "nt"
                else shlex.join([sys.executable, str(script)])
            )
            spec = shell.ShellHookSpec(
                event="pre_tool_call", command=command, timeout=1, fail_closed=True
            )
            result = shell.run_once(
                spec, {"tool_name": "terminal", "args": {}, "session_id": "fixture"}
            )
            check(name + "_fails_closed", result["parsed"]["action"] == "block")
        missing = shell.ShellHookSpec(
            event="pre_tool_call", command=str(root / "missing-executable"), fail_closed=True
        )
        check(
            "missing_executable_fails_closed",
            shell.run_once(missing, {})["parsed"]["action"] == "block",
        )
        for event in ("on_session_start", "on_session_reset", "on_session_finalize"):
            result = shell.run_once(specs[event], {"session_id": "conversation"})
            check(event + "_installed_callback", result["returncode"] == 0)
    return {
        "ok": True,
        "hermes_version": HERMES_VERSION,
        "hermes_revision": HERMES_REVISION,
        "checks": checks,
        "live_model": False,
        "real_tool_execution": False,
        "fixtures": [
            "profile",
            "environment",
            "approval UI",
            "ACP",
            "post-hook suppression",
            "tool recorder",
        ],
        "coverage_limit": "Other modifying hooks and execution middleware can rewrite after review; use an isolated profile without them.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source", type=Path, help="Use local sources, still checked against every pinned SHA256"
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    report = run(args.source)
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
