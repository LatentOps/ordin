"""Actual ToolNode wrapper and post-validation synchronous tool boundary."""

from contextvars import ContextVar
import inspect
from typing import Any

from ordin._runtime_json import digest
from ordin_swarm.sdk import SwarmSDK, SwarmToolRefused, bounded_json, callback_binding
from .contracts import coverage, require_version


class LangGraphAdapter:
    def __init__(self, sdk: SwarmSDK, session, *, operator: object):
        require_version("langgraph")
        if type(sdk) is not SwarmSDK or operator is not sdk._operator:
            raise ValueError("original SDK operator required")
        sdk.context(session)
        self.sdk, self.session, self._operator = sdk, session, operator
        self.node: Any = None
        self._records: dict[str, tuple] = {}
        self._closed = False
        self._installing = False
        self._current: ContextVar[Any] = ContextVar("ordin-langgraph-call", default=None)
        self._wrapper, self._awrapper = self._wrap, self._awrap

    def tool_node(self, tools, *, action_builders=None, handle_tool_errors=True):
        from langgraph.prebuilt import ToolNode
        from langchain_core.tools import StructuredTool

        if (
            self.node is not None
            or self._closed
            or type(tools) not in {tuple, list}
            or not 1 <= len(tools) <= 256
            or len({v.name for v in tools}) != len(tools)
        ):
            raise ValueError("one bounded unique original ToolNode installation required")
        self._installing = True
        proxies = []
        try:
            for original in tools:
                if (
                    type(original) is not StructuredTool
                    or original.func is None
                    or original.coroutine is not None
                    or inspect.iscoroutinefunction(original.func)
                ):
                    raise ValueError(
                        "this pinned route requires original synchronous StructuredTools"
                    )
                if set(original.get_input_schema().model_fields) != set(
                    original.tool_call_schema.model_fields
                ) or {"config", "callbacks"}.intersection(
                    inspect.signature(original.func).parameters
                ):
                    raise ValueError("injected state/store/runtime/config is not represented")
                snapshot = self._tool_binding(original)
                function = original.func

                def invoke(arguments, function=function):
                    value = function(**arguments)
                    # Data-only results cannot inject native Command/Send
                    # control flow into unmediated graph branches.
                    bounded_json(value)
                    return value

                holder: list[Any] = []

                def make_guarded(holder):
                    def run(**arguments):
                        current = self._current.get()
                        if current is None or current[0].tool is not holder[0] or current[1]:
                            raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
                        current[1] = True
                        return self.sdk.invoke(
                            self.session,
                            holder[1],
                            arguments,
                            request_id=current[0].tool_call["id"],
                        )

                    return run

                guarded = make_guarded(holder)
                proxy = StructuredTool.from_function(
                    guarded,
                    name=original.name,
                    description=original.description,
                    args_schema=original.args_schema,
                    return_direct=original.return_direct,
                )
                proxy_key = self._tool_binding(proxy)

                def guard(original=original, snapshot=snapshot, proxy=proxy, proxy_key=proxy_key):
                    require_version("langgraph")
                    if (
                        self._closed
                        or self._tool_binding(original) != snapshot
                        or self._tool_binding(proxy) != proxy_key
                        or (
                            not self._installing
                            and (
                                self.node._wrap_tool_call is not self._wrapper
                                or self.node._awrap_tool_call is not self._awrapper
                                or self.node._tools_by_name.get(proxy.name) is not proxy
                            )
                        )
                    ):
                        raise ValueError("original ToolNode/tool configuration changed")

                handle = self.sdk.register_tool(
                    self.session,
                    name=original.name,
                    runtime="langgraph",
                    callback=invoke,
                    guard=guard,
                    action_builder=(action_builders or {}).get(original.name),
                    operator=self._operator,
                )
                holder.extend((proxy, handle))
                self._records[original.name] = (proxy, original, handle)
                proxies.append(proxy)
            self.node = ToolNode(
                proxies,
                wrap_tool_call=self._wrapper,
                awrap_tool_call=self._awrapper,
                handle_tool_errors=handle_tool_errors,
            )
            self._installing = False
            return self.node
        except Exception:
            self._closed = True
            self._installing = False
            raise

    @staticmethod
    def _tool_binding(tool):
        return (
            tool.name,
            callback_binding(tool.func),
            id(tool.coroutine),
            digest(bounded_json(tool.get_input_schema().model_json_schema())),
        )

    def _wrap(self, request, execute):
        from langgraph.prebuilt.tool_node import ToolCallRequest

        if type(request) is not ToolCallRequest or not callable(execute):
            raise ValueError("original native ToolNode request required")
        call = bounded_json(request.tool_call)
        known = self._records.get(call.get("name"))
        if (
            known is None
            or request.tool is not known[0]
            or set(call) - {"name", "args", "id", "type"}
            or type(call.get("args")) is not dict
        ):
            raise SwarmToolRefused("deny", ("framework.tool_identity_unverified",))
        if set(call["args"]) - set(known[0].get_input_schema().model_fields):
            raise SwarmToolRefused("deny", ("framework.unrepresented_arguments",))
        self.sdk._tools[known[2]].guard()
        captured = request.override(tool_call=call)
        token = self._current.set([captured, False])
        try:
            return execute(captured)
        finally:
            self._current.reset(token)

    async def _awrap(self, request, execute):
        raise SwarmToolRefused("deny", ("framework.native_async_route_unavailable",))

    def status(self):
        connected = False
        if not self._closed and self.node is not None:
            try:
                self.sdk.context(self.session)
                for _, _, tool in self._records.values():
                    self.sdk._tools[tool].guard()
                connected = (
                    self.node._wrap_tool_call is self._wrapper
                    and self.node._awrap_tool_call is self._awrapper
                )
            except (ValueError, AttributeError, TypeError):
                pass
        return coverage("langgraph", installed=self.node is not None, connected=connected)

    def close(self):
        self._closed = True
        self.sdk.close(self.session)

    @staticmethod
    def plan_existing(node):
        from langgraph.prebuilt import ToolNode

        return {
            "supported": False,
            "restart_required": True,
            "reason_code": "framework.rebuild_toolnode_and_graph_required",
            "execution_authority": False,
            "recognized": type(node) is ToolNode,
        }


__all__ = ["LangGraphAdapter"]
