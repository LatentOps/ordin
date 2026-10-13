"""Hermes native shell hooks over Ordin's review and session boundary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .action import ActionEnvelope
from .action_policy import load_action_policy
from .adapters import MCPAdapter, ToolCallAdapter
from .agent import AgentDecision, AgentGate
from .api import Ordin
from .audit import JsonlAuditSink
from .context import ExecutionContext
from .execution import ActionObservation
from .mcp_proxy import _parse_json_value, _parse_jsonrpc_line
from .policy import ReviewPolicy, validate_fail_threshold
from .session import IntegrationSession, SessionIdentity, SqliteSessionStore
from .tool_calls import (
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
    load_tool_semantics,
)
from .trace_capture import TraceRecorder, attach_trace, digest, raw_capture_flag


HERMES_RUNTIME = "hermes"
HERMES_VERSION = "v0.21.7"
HERMES_REVISION = "71d34bad1045610252eda02ee79549436896e784"
MAX_HOOK_BYTES = 1_048_576
_BUILTINS = {
    "terminal",
    "read_file",
    "write_file",
    "patch",
    "search_files",
    "execute_code",
    "delegate_task",
    "ordin.unmodeled_terminal",
    "ordin.unmodeled_file",
}
_EVENTS = {
    "pre": "pre_tool_call",
    "post": "post_tool_call",
    "session-start": "on_session_start",
    "session-reset": "on_session_reset",
    "session-end": "on_session_finalize",
}


def _text(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} requires bounded non-empty text")
    return value


def _identity(payload: Mapping[str, Any]) -> SessionIdentity:
    return SessionIdentity(
        HERMES_RUNTIME,
        digest(
            [
                _text(payload.get("profile"), "profile", 256),
                _text(payload.get("session_id"), "session_id"),
            ]
        ),
    )


def load_hermes_mcp_map(path: str | Path) -> Mapping[str, tuple[str, str]]:
    """Only operator-reviewed exact aliases bind a host tool to MCP semantics."""
    from ._json_contracts import load_configuration

    value = load_configuration(path, label="Hermes MCP mapping", maximum=MAX_HOOK_BYTES)
    if set(value) != {"tools"} or not isinstance(value["tools"], list) or len(value["tools"]) > 256:
        raise ValueError("invalid Hermes MCP mapping")
    result: dict[str, tuple[str, str]] = {}
    for entry in value["tools"]:
        if not isinstance(entry, dict) or set(entry) != {"hook_name", "server", "tool"}:
            raise ValueError("invalid Hermes MCP alias")
        alias = _text(entry["hook_name"], "hook_name", 256)
        if alias in result or alias in _BUILTINS:
            raise ValueError("duplicate or shadowing Hermes MCP alias")
        server, tool = _text(entry["server"], "server", 256), _text(entry["tool"], "tool", 256)
        MCPAdapter(server=server).adapt(tool, {})
        result[alias] = (server, tool)
    return MappingProxyType(result)


def build_hermes_integration(
    *,
    semantics_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    mcp_map_path: str | Path | None = None,
    audit_path: str | Path | None = None,
    trace_path: str | Path | None = None,
    raw_local: bool = False,
    fail_on: str = "warn",
) -> HermesIntegration:
    aliases = load_hermes_mcp_map(mcp_map_path) if mcp_map_path else {}
    rules = [
        ToolSemanticRule(
            id="hermes-" + name,
            kind="tool",
            runtime=HERMES_RUNTIME,
            tool=name,
            effects=effects,
            resources=(ToolResourceBinding("path", "path"),),
        )
        for name, effects in [
            ("read_file", ("filesystem.read",)),
            ("write_file", ("filesystem.write",)),
            ("patch", ("filesystem.write",)),
        ]
    ]
    if semantics_path:
        rules.extend(load_tool_semantics(semantics_path).registry.rules)
    ordin = Ordin(
        tool_semantics=ToolSemanticsRegistry("ordin.hermes", "1", tuple(rules)),
        action_policy=load_action_policy(policy_path) if policy_path else None,
        policy=ReviewPolicy(validate_fail_threshold(fail_on)),
        audit=JsonlAuditSink(audit_path) if audit_path else None,
    )
    ordin, trace = attach_trace(
        ordin,
        trace_path,
        integration=HERMES_RUNTIME,
        raw_local=raw_local,
        configuration={"aliases": dict(aliases), "contract": HERMES_REVISION},
    )
    return HermesIntegration(gate=AgentGate(ordin), mcp_map=aliases, trace=trace)


def _default_gate() -> AgentGate:
    return build_hermes_integration().gate


@dataclass(frozen=True)
class HermesIntegration:
    gate: AgentGate = field(default_factory=_default_gate)
    mcp_map: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    session: IntegrationSession | None = None
    trace: TraceRecorder | None = None

    def __post_init__(self) -> None:
        if len(self.mcp_map) > 256:
            raise ValueError("too many Hermes MCP aliases")
        for alias, identity in self.mcp_map.items():
            _text(alias, "MCP alias", 256)
            if alias in _BUILTINS or not isinstance(identity, tuple) or len(identity) != 2:
                raise ValueError("Hermes aliases require exact server/tool identities")
            MCPAdapter(server=identity[0]).adapt(identity[1], {})
        object.__setattr__(self, "mcp_map", MappingProxyType(dict(self.mcp_map)))

    def adapt(self, payload: Mapping[str, Any]) -> ActionEnvelope:
        if payload.get("hook_event_name") != "pre_tool_call":
            raise ValueError("expected Hermes pre_tool_call")
        identity = _identity(payload)
        extra = payload.get("extra")
        if not isinstance(extra, Mapping):
            raise ValueError("Hermes extra must be an object")
        call = _text(extra.get("tool_call_id"), "tool_call_id")
        tool = _text(payload.get("tool_name"), "tool_name", 256)
        arguments = payload.get("tool_input")
        if not isinstance(arguments, Mapping):
            raise ValueError("Hermes tool_input must be an object")
        original_digest = digest(dict(arguments))
        # The hook's cwd is Hermes' process cwd, not the terminal/file backend cwd.
        context = ExecutionContext(agent=HERMES_RUNTIME)
        shell_tools: frozenset[str] = frozenset()
        if tool == "terminal":
            supported = set(arguments) <= {
                "command",
                "workdir",
                "timeout",
                "background",
                "pty",
                "force",
            }
            supported = supported and all(
                arguments.get(key, False) is False for key in ("background", "pty", "force")
            )
            timeout = arguments.get("timeout")
            # A timeout can promote a foreground call into a background job in Hermes.
            supported = supported and timeout is None
            command = _text(arguments.get("command"), "command", MAX_HOOK_BYTES)
            if supported:
                workdir = arguments.get("workdir")
                if workdir is not None:
                    workdir = _text(workdir, "workdir")
                    if not (
                        PurePosixPath(workdir).is_absolute()
                        or PureWindowsPath(workdir).is_absolute()
                    ):
                        raise ValueError("terminal workdir must be absolute")
                    context = ExecutionContext(cwd=workdir, agent=HERMES_RUNTIME)
                arguments = {"command": command}
                shell_tools = frozenset({"terminal"})
            else:
                # Unknown execution modes cannot inherit ordinary foreground shell semantics.
                tool = "ordin.unmodeled_terminal"
                arguments = {"input_digest": original_digest}
        elif tool in {"read_file", "write_file", "patch"}:
            allowed_fields = {
                "read_file": {"path", "offset", "limit"},
                "write_file": {"path", "content", "cross_profile"},
                "patch": {"path", "mode", "old_string", "new_string", "replace_all"},
            }
            supported = (
                set(arguments) <= allowed_fields[tool]
                and arguments.get("cross_profile", False) is False
            )
            if tool == "patch":
                supported = supported and arguments.get("mode", "replace") == "replace"
            if supported:
                arguments = {
                    "path": _text(arguments.get("path"), "path"),
                    "input_digest": original_digest,
                }
            else:
                tool = "ordin.unmodeled_file"
                arguments = {"input_digest": original_digest}
        elif tool in {"execute_code", "delegate_task"}:
            arguments = {"input_digest": original_digest}
        mapped = self.mcp_map.get(payload["tool_name"])
        action_id = "hermes:" + digest(
            [identity.key, call, tool, original_digest, mapped, HERMES_REVISION]
        )
        if mapped:
            server, name = mapped
            action = MCPAdapter(server=server).adapt(
                name, arguments, context=context, action_id=action_id
            )
        else:
            action = ToolCallAdapter(runtime=HERMES_RUNTIME, shell_tools=shell_tools).adapt(
                tool,
                arguments,
                context=context,
                action_id=action_id,
            )
        return replace(
            action,
            parameters={
                **action.parameters,
                "input_digest": original_digest,
                "integration": {
                    "runtime": HERMES_RUNTIME,
                    "session_id_sha256": identity.key,
                    "tool_use_id_sha256": digest(call),
                    "host_contract_sha256": digest(HERMES_REVISION),
                },
            },
        )

    def review_pre_tool(self, payload: Mapping[str, Any]) -> AgentDecision:
        if self.session is not None:
            self.session.require_identity(_identity(payload))
            if self.session.gate is not self.gate:
                raise ValueError("Hermes integration must use its session gate")
            return self.session.evaluate(self.adapt(payload))
        return self.gate.evaluate_action(self.adapt(payload))

    def pre_tool_output(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        decision = self.review_pre_tool(payload)
        if decision.may_execute:
            return {}
        return {
            "action": "block" if decision.disposition == "deny" else "approve",
            "message": f"Ordin {decision.review.decision}/{decision.review.risk}",
            # Approval allowlists must not grant every future call of this tool.
            "rule_key": "ordin:" + digest(self.adapt(payload).as_dict()),
        }

    def observation_from_hook(
        self,
        payload: Mapping[str, Any],
        *,
        observed_effects: tuple[str, ...] = (),
    ) -> ActionObservation | None:
        if payload.get("hook_event_name") != "post_tool_call":
            raise ValueError("expected Hermes post_tool_call")
        identity = _identity(payload)
        if self.session is not None:
            self.session.require_identity(identity)
            if self.session.gate is not self.gate:
                raise ValueError("Hermes integration must use its session gate")
        action = self.adapt({**payload, "hook_event_name": "pre_tool_call"})
        extra = payload["extra"]
        host_status = extra.get("status")
        if host_status == "blocked":
            return None
        if host_status not in {"ok", "error"}:
            raise ValueError("unknown Hermes post-tool status")
        result = extra.get("result")
        if not isinstance(result, str) or len(result.encode()) > MAX_HOOK_BYTES:
            raise ValueError("Hermes result must be bounded JSON text")
        value = _parse_json_value(result.encode())
        exit_code = None
        status = "failure" if host_status == "error" else "reported"
        if payload["tool_name"] == "terminal" and isinstance(value, Mapping):
            candidate = value.get("exit_code")
            if candidate is not None:
                if isinstance(candidate, bool) or not isinstance(candidate, int):
                    raise ValueError("Hermes exit_code must be integer")
                exit_code = candidate
                status = (
                    "success"
                    if candidate == 0 and host_status == "ok" and not value.get("error")
                    else "failure"
                )
        assert action.action_id is not None
        observation = ActionObservation(
            action.action_id,
            exit_code=exit_code,
            effects=observed_effects,
            metadata={"runtime": HERMES_RUNTIME, "status": status},
        )
        if self.session is not None:
            self.session.observe(observation)
        if self.trace is not None:
            self.trace.record_observation(observation, session_key=identity.key)
        return observation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ordin-hermes-hook")
    parser.add_argument("mode", choices=(*_EVENTS, "doctor"))
    parser.add_argument("--root", type=Path, help="Read verified Ordin-owned Hermes setup settings")
    args = parser.parse_args(argv)
    try:
        environment = dict(os.environ)
        if args.root is not None:
            from .setup import hook_environment, load_owned

            root = args.root.expanduser().absolute()
            environment.update(hook_environment(load_owned(root, "hermes"), root))
        integration = build_hermes_integration(
            semantics_path=environment.get("ORDIN_HERMES_SEMANTICS") or None,
            policy_path=environment.get("ORDIN_HERMES_POLICY") or None,
            mcp_map_path=environment.get("ORDIN_HERMES_MCP_MAP") or None,
            audit_path=environment.get("ORDIN_HERMES_AUDIT") or None,
            trace_path=environment.get("ORDIN_HERMES_TRACE") or None,
            raw_local=raw_capture_flag(environment.get("ORDIN_HERMES_TRACE_RAW", "0")),
            fail_on=environment.get("ORDIN_HERMES_FAIL_ON", "warn"),
        )
        if args.mode == "doctor":
            print(
                json.dumps(
                    {
                        "integration": HERMES_RUNTIME,
                        "contract_version": HERMES_VERSION,
                        "contract_revision": HERMES_REVISION,
                        "host_enablement_verified": False,
                        "state_enabled": bool(environment.get("ORDIN_HERMES_STATE")),
                        "pre_tool_ask_enforced": True,
                        "requires_fail_closed": True,
                    }
                )
            )
            return 0
        raw = sys.stdin.read(MAX_HOOK_BYTES + 1).encode()
        if len(raw) > MAX_HOOK_BYTES:
            raise ValueError("Hermes hook exceeds byte limit")
        payload = _parse_jsonrpc_line(raw)
        if payload.get("hook_event_name") != _EVENTS[args.mode]:
            raise ValueError("Hermes hook event/mode mismatch")
        identity = _identity(payload)
        output: dict[str, Any] = {}

        def run(active: HermesIntegration) -> None:
            nonlocal output
            if args.mode == "pre":
                output = active.pre_tool_output(payload)
            elif args.mode == "post":
                active.observation_from_hook(payload)
            elif args.mode == "session-end" and active.session:
                active.session.end()
            if args.mode in {"session-reset", "session-end"} and active.trace:
                active.trace.record_boundary(identity.key)

        state_path = environment.get("ORDIN_HERMES_STATE")
        if state_path:
            # Hermes resumes sessions and delegates without consistently emitting a new
            # start callback. Initialize only on start/review; never on post evidence.
            with SqliteSessionStore(state_path).transaction(
                identity,
                integration.gate,
                create=args.mode in {"session-start", "session-reset", "pre"},
                reset=args.mode == "session-reset",
            ) as session:
                run(replace(integration, session=session))
        else:
            run(integration)
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        if args.mode == "pre":
            print(
                json.dumps(
                    {
                        "action": "block",
                        "message": "Ordin Hermes review unavailable; check input, configuration and state",
                    }
                )
            )
        else:
            print(
                "ordin-hermes-hook: invalid input or unavailable configuration/state",
                file=sys.stderr,
            )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
