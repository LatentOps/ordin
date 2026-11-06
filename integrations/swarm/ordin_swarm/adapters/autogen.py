"""Pinned legacy AutoGen Core runtime envelopes and native FunctionTools.

Upstream is archived. This adapter deliberately does not advertise maintenance
or support for distributed runtimes without this intervention contract.
"""

from functools import wraps
import inspect
import json
from threading import RLock
from typing import Any

from ordin._runtime_json import digest
from ordin_swarm.sdk import SwarmSDK, SwarmToolRefused, bounded_json, callback_binding
from .contracts import coverage, require_version


class AutoGenAdapter:
    def __init__(self):
        require_version("autogen")
        from autogen_core import DefaultInterventionHandler, SingleThreadedAgentRuntime

        owner = self

        class Handler(DefaultInterventionHandler):
            async def on_send(self, message, *, message_context, recipient):
                return owner._on_send(message, message_context, recipient)

            async def on_publish(self, message, *, message_context):
                from autogen_core import FunctionCall

                if isinstance(message, FunctionCall):
                    raise SwarmToolRefused("deny", ("framework.native_broadcast_tool_unavailable",))
                return message

        self._handler = Handler()
        self.runtime = SingleThreadedAgentRuntime(intervention_handlers=[self._handler])
        self._routes: dict[Any, dict] = {}
        self._scopes: dict[Any, list] = {}
        self._lock = RLock()
        self._run_context = None
        self._closed = False

    def bind(self, sdk: SwarmSDK, session, *, producer, recipient, operator: object):
        from autogen_core import AgentId

        if (
            type(sdk) is not SwarmSDK
            or operator is not sdk._operator
            or type(producer) is not AgentId
            or type(recipient) is not AgentId
            or sdk._session(session).runtime is not self.runtime
        ):
            raise ValueError("original SDK session/runtime and native agent routing pair required")
        with self._lock:
            if (
                self._run_context is not None
                or self._closed
                or recipient in self._routes
                or len(self._routes) >= 256
            ):
                raise ValueError("AutoGen route requires fresh bounded pre-start registration")
            self._routes[recipient] = {
                "sdk": sdk,
                "session": session,
                "producer": producer,
                "tools": {},
                "requests": set(),
            }

    def function_tool(
        self, recipient, function, *, name: str, description: str, action_builder=None
    ):
        from autogen_core.tools import FunctionTool

        if not callable(function) or inspect.iscoroutinefunction(function):
            raise ValueError("only synchronous original function callbacks are represented")
        with self._lock:
            route = self._routes.get(recipient)
            if route is None or self._run_context is not None or name in route["tools"]:
                raise ValueError("original fresh AutoGen route/tool required")
            holder: list[Any] = []
            signature = inspect.signature(function)

            @wraps(function)
            def wrapped(*args, **kwargs):
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = bounded_json(dict(bound.arguments))
                with self._lock:
                    scope = self._scopes.get(recipient)
                    if (
                        scope is None
                        or scope[0] is not holder[0]
                        or scope[3]
                        or digest(arguments) != scope[2]
                    ):
                        raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
                    scope[3] = True
                    request_id = scope[1]
                try:
                    return route["sdk"].invoke(
                        route["session"], holder[1], arguments, request_id=request_id
                    )
                finally:
                    with self._lock:
                        if self._scopes.get(recipient) is scope:
                            self._scopes.pop(recipient, None)

            native = FunctionTool(wrapped, description=description, name=name)
            key = callback_binding(function)
            schema = digest(bounded_json(native.args_type().model_json_schema()))

            def guard():
                require_version("autogen")
                if (
                    self._closed
                    or self._run_context is None
                    or self.runtime._run_context is not self._run_context
                    or native._func is not wrapped
                    or native.name != name
                    or callback_binding(function) != key
                    or digest(bounded_json(native.args_type().model_json_schema())) != schema
                ):
                    raise ValueError("original AutoGen runtime/tool binding changed")

            def invoke(arguments):
                return function(**arguments)

            # Register before start; full live guard is used at every call.
            initializing = [True]

            def configured_guard():
                if not initializing[0]:
                    guard()

            handle = route["sdk"].register_tool(
                route["session"],
                name=name,
                runtime="autogen",
                callback=invoke,
                guard=configured_guard,
                action_builder=action_builder,
                operator=route["sdk"]._operator,
            )
            initializing[0] = False
            holder.extend((native, handle))
            route["tools"][name] = (native, guard)
            return native

    @staticmethod
    def _arguments(raw):
        if type(raw) is not str or len(raw.encode()) > 65536:
            raise ValueError("bounded native tool JSON required")

        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ValueError("duplicate native JSON field")
                result[key] = value
            return result

        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite native JSON")),
        )
        if type(value) is not dict:
            raise ValueError("native tool arguments must be an object")
        return value

    def _on_send(self, message, context, recipient):
        from autogen_core import FunctionCall
        from autogen_core.tool_agent import ToolException

        if not isinstance(message, FunctionCall):
            return message
        if type(message) is not FunctionCall:
            raise SwarmToolRefused("deny", ("framework.native_message_type_unverified",))
        with self._lock:
            route = self._routes.get(recipient)
            known = route["tools"].get(message.name) if route is not None else None
            try:
                if (
                    route is None
                    or context.sender != route["producer"]
                    or known is None
                    or recipient in self._scopes
                ):
                    raise ValueError("unverified native producer/recipient/tool route")
                known[1]()
                if (
                    type(message.id) is not str
                    or not 1 <= len(message.id) <= 256
                    or len(route["requests"]) >= 4096
                    or digest(message.id) in route["requests"]
                ):
                    raise ValueError("native request replay or bounded capacity")
                route["requests"].add(digest(message.id))
                raw = self._arguments(message.arguments)
                model = known[0].args_type()
                if set(raw) - set(model.model_fields):
                    raise ValueError("unrepresented native arguments")
                normalized = bounded_json(model.model_validate(raw).model_dump())
                self._scopes[recipient] = [known[0], message.id, digest(normalized), False]
                return message
            except (ValueError, TypeError):
                raise ToolException(
                    call_id=message.id,
                    name=message.name,
                    content="Ordin denied unverified native tool routing",
                ) from None

    def start(self):
        if self._closed or self._run_context is not None:
            raise ValueError("fresh AutoGen lifecycle required")
        self.runtime.start()
        self._run_context = self.runtime._run_context

    async def stop(self):
        self._closed = True
        try:
            if self.runtime._run_context is self._run_context and self._run_context is not None:
                # Archived 0.7.5 does not task_done() an intervention-denied
                # envelope; stop_when_idle() can wait forever after a denial.
                # The documented immediate stop fences queued work. It cannot
                # roll back an already-running host callback.
                await self.runtime.stop()
        finally:
            self._closed = True
            for row in self._routes.values():
                row["sdk"].close(row["session"])

    def status(self):
        return coverage(
            "autogen",
            installed=True,
            connected=not self._closed
            and self._run_context is not None
            and self.runtime._run_context is self._run_context,
        )

    @staticmethod
    def plan_existing(runtime):
        return {
            "supported": False,
            "restart_required": True,
            "reason_code": "framework.new_runtime_with_original_intervention_handler_required",
            "execution_authority": False,
        }


__all__ = ["AutoGenAdapter"]
