"""Native ToolNode boundaries after argument validation, with one-use scopes."""

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
import inspect
from threading import get_ident
from typing import TYPE_CHECKING, Any

from ordin._runtime_json import digest
from ordin_swarm.sdk import SwarmSDK, SwarmToolRefused, bounded_json, callback_binding
from .contracts import coverage, require_version

if TYPE_CHECKING:
    from pydantic import BaseModel


def _argument_schema(tool, *, call=False) -> "type[BaseModel]":
    from pydantic import BaseModel

    schema = tool.tool_call_schema if call else tool.get_input_schema()
    if not isinstance(schema, type) or not issubclass(schema, BaseModel):
        raise ValueError("this pinned route requires Pydantic v2 argument models")
    return schema


def _task():
    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


@dataclass
class _NativeScope:
    request: Any
    mode: str
    stage: str = "new"
    active: bool = True
    cancelled: bool = False
    wrapper_task: Any = None
    native_task: Any = None
    native_coroutine: Any = None
    thread_id: int | None = None


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
        self._async_lock: asyncio.Lock | None = None
        self._async_loop: asyncio.AbstractEventLoop | None = None
        self._native_work: set[Any] = set()
        self._wrapper, self._awrapper = self._wrap, self._awrap

    def tool_node(self, tools, *, action_builders=None, handle_tool_errors=True):
        from langgraph.prebuilt import ToolNode
        from langchain_core.tools import StructuredTool
        from langchain_core.runnables import RunnableConfig
        from langchain_core.tools.base import _get_runnable_config_param

        owner = self
        row = self.sdk._session(self.session)
        async_supported = row.broker is None and row.coordinator is None

        class _BoundStructuredTool(StructuredTool):
            def invoke(self, *args, **kwargs):
                owner._native_entry(self, "invoke")
                return super().invoke(*args, **kwargs)

            def run(self, *args, **kwargs):
                owner._native_entry(self, "run")
                return super().run(*args, **kwargs)

            def _run(self, *args, config=None, run_manager=None, **kwargs):
                owner._native_entry(self, "_run")
                return super()._run(*args, config=config, run_manager=run_manager, **kwargs)

            def _to_args_and_kwargs(self, *args, **kwargs):
                owner._native_entry(self, "validate")
                result = super()._to_args_and_kwargs(*args, **kwargs)
                owner._native_entry(self, "validated")
                return result

            async def ainvoke(self, *args, **kwargs):
                owner._native_entry(self, "ainvoke")
                return await super().ainvoke(*args, **kwargs)

            async def arun(self, *args, **kwargs):
                owner._native_entry(self, "arun")
                return await super().arun(*args, **kwargs)

            def _arun(self, *args, config=None, run_manager=None, **kwargs):
                scope = owner._native_entry(self, "_arun_create")

                async def native_arun():
                    owner._native_entry(self, "_arun")
                    return await super(_BoundStructuredTool, self)._arun(
                        *args, config=config, run_manager=run_manager, **kwargs
                    )

                scope.native_coroutine = native_arun()
                return scope.native_coroutine

        # These local proxy methods retain the pinned native config-injection
        # signature without importing an optional SDK at module import time.
        _BoundStructuredTool._run.__annotations__["config"] = RunnableConfig
        _BoundStructuredTool._arun.__annotations__["config"] = RunnableConfig

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
                    or (original.func is None and original.coroutine is None)
                    or (original.func is not None and inspect.iscoroutinefunction(original.func))
                    or (
                        original.coroutine is not None
                        and not inspect.iscoroutinefunction(original.coroutine)
                    )
                ):
                    raise ValueError("original synchronous/coroutine StructuredTool required")
                if original.coroutine is not None and not async_supported:
                    raise ValueError(
                        "native coroutine callbacks require an intercepted async gateway"
                    )
                if set(_argument_schema(original).model_fields) != set(
                    _argument_schema(original, call=True).model_fields
                ) or any(
                    function is not None
                    and (
                        {"config", "callbacks", "run_manager"}.intersection(
                            inspect.signature(function).parameters
                        )
                        or _get_runnable_config_param(function) is not None
                    )
                    for function in (original.func, original.coroutine)
                ):
                    raise ValueError("injected state/store/runtime/config is not represented")
                snapshot = self._tool_binding(original)
                holder: list[Any] = [None, None, None]

                def make_guarded(holder):
                    def run(**arguments):
                        current = self._consume(holder[0], asynchronous=False)
                        value = self.sdk.invoke(
                            self.session,
                            holder[1],
                            arguments,
                            request_id=current.request.tool_call["id"],
                        )
                        if current.cancelled or not current.active:
                            raise SwarmToolRefused(
                                "deny", ("framework.async_cancellation_unknown",)
                            )
                        return value

                    return run

                def make_aguarded(holder):
                    async def run(**arguments):
                        current = self._consume(holder[0], asynchronous=True)
                        return await self.sdk.invoke_async(
                            self.session,
                            holder[2],
                            arguments,
                            request_id=current.request.tool_call["id"],
                        )

                    return run

                proxy = _BoundStructuredTool.from_function(
                    func=make_guarded(holder) if original.func is not None else None,
                    coroutine=make_aguarded(holder) if async_supported else None,
                    name=original.name,
                    description=original.description,
                    args_schema=original.args_schema,
                    return_direct=original.return_direct,
                    response_format=original.response_format,
                    handle_tool_error=original.handle_tool_error,
                    handle_validation_error=original.handle_validation_error,
                )
                holder[0] = proxy
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

                if original.func is not None:

                    def invoke(arguments, function=original.func):
                        current = self._current.get()
                        if current is None or current.cancelled or not current.active:
                            raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
                        value = function(**arguments)
                        bounded_json(value)
                        if current.cancelled or not current.active:
                            from ordin.swarm.gateway import GatewayOutcome

                            return GatewayOutcome(None, "pending")
                        return value

                    holder[1] = self.sdk.register_tool(
                        self.session,
                        name=original.name,
                        runtime="langgraph",
                        callback=invoke,
                        guard=guard,
                        action_builder=(action_builders or {}).get(original.name),
                        operator=self._operator,
                    )
                if original.coroutine is not None:

                    async def ainvoke(arguments, function=original.coroutine):
                        current = self._current.get()
                        if current is None or current.cancelled or not current.active:
                            raise asyncio.CancelledError
                        value = await function(**arguments)
                        if current.cancelled or not current.active:
                            raise asyncio.CancelledError
                        return value

                    holder[2] = self.sdk.register_async_tool(
                        self.session,
                        name=original.name,
                        runtime="langgraph",
                        callback=ainvoke,
                        guard=guard,
                        action_builder=(action_builders or {}).get(original.name),
                        operator=self._operator,
                    )
                elif async_supported:
                    # The native async entry keeps post-Pydantic validation,
                    # while the existing synchronous callback executes in an
                    # owned thread without gateway/SDK thread locks held.
                    holder[2] = holder[1]
                self._records[original.name] = (proxy, original, holder[1], holder[2])
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
            id(type(tool)),
            tool.name,
            callback_binding(tool.func),
            callback_binding(tool.coroutine),
            digest(bounded_json(_argument_schema(tool).model_json_schema())),
            tool.return_direct,
            tool.response_format,
            callback_binding(tool.handle_tool_error)
            if callable(tool.handle_tool_error)
            else tool.handle_tool_error,
            callback_binding(tool.handle_validation_error)
            if callable(tool.handle_validation_error)
            else tool.handle_validation_error,
            tuple(
                callback_binding(getattr(method, "__func__", method))
                for method in (
                    getattr(tool, name)
                    for name in (
                        "invoke",
                        "run",
                        "_run",
                        "ainvoke",
                        "arun",
                        "_arun",
                        "_to_args_and_kwargs",
                    )
                )
            ),
        )

    def _capture(self, request, execute):
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
        schema = _argument_schema(known[0])
        allowed = set(schema.model_fields) | set(schema.model_json_schema().get("properties", {}))
        if set(call["args"]) - allowed:
            raise SwarmToolRefused("deny", ("framework.unrepresented_arguments",))
        for handle in known[2:]:
            if handle is not None:
                self.sdk._tools[handle].guard()
        return request.override(tool_call=call), known

    def _wrap(self, request, execute):
        if self._current.get() is not None:
            raise SwarmToolRefused("deny", ("framework.inherited_native_scope",))
        captured, _ = self._capture(request, execute)
        scope = _NativeScope(captured, "sync", thread_id=get_ident())
        token = self._current.set(scope)
        try:
            return execute(captured)
        finally:
            scope.active = False
            self._current.reset(token)

    async def _awrap(self, request, execute):
        if self._current.get() is not None or self.sdk._async_session_active(self.session):
            raise SwarmToolRefused("deny", ("framework.inherited_native_scope",))
        loop = asyncio.get_running_loop()
        if self._async_loop is None:
            self._async_loop, self._async_lock = loop, asyncio.Lock()
        elif self._async_loop is not loop:
            raise ValueError("original LangGraph async event loop required")
        lock = self._async_lock
        if lock is None:
            raise ValueError("original native async lock required")
        async with lock:
            captured, known = self._capture(request, execute)
            if known[3] is None:
                raise SwarmToolRefused("deny", ("framework.async_owned_route_unavailable",))
            if len(self._native_work) >= self.sdk._limits[2]:
                raise ValueError("native async work capacity reached")
            scope = _NativeScope(captured, "async")
            token = self._current.set(scope)

            async def native():
                scope.wrapper_task = asyncio.current_task()
                return await execute(captured)

            work = asyncio.create_task(native())
            self._native_work.add(work)

            def completed(task):
                self._native_work.discard(task)
                try:
                    task.exception()
                except BaseException:
                    pass

            work.add_done_callback(completed)
            try:
                return await asyncio.shield(work)
            except asyncio.CancelledError:
                scope.cancelled = True
                work.cancel()
                raise
            finally:
                scope.active = False
                scope.native_task = scope.wrapper_task = scope.native_coroutine = None
                self._current.reset(token)

    def _native_entry(self, proxy, entry):
        scope = self._current.get()
        if scope is None or not scope.active or scope.cancelled or scope.request.tool is not proxy:
            raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
        task, thread = _task(), get_ident()
        if (
            entry == "ainvoke"
            and scope.mode != "sync"
            and scope.stage == "new"
            and task is scope.wrapper_task
        ):
            scope.stage = "async_invoked"
            return
        if entry == "invoke" and (
            scope.mode == "sync" and scope.stage == "new" and scope.thread_id == thread
        ):
            scope.thread_id, scope.stage = thread, "sync_invoked"
            return
        if entry == "run" and scope.stage == "sync_invoked" and scope.thread_id == thread:
            scope.stage = "sync_running"
            return
        if (
            entry == "arun"
            and scope.mode == "async"
            and scope.stage == "async_invoked"
            and task is scope.wrapper_task
        ):
            scope.stage = "async_running"
            return
        original = (
            scope.mode == "sync"
            and scope.thread_id == thread
            or scope.mode == "async"
            and task is scope.wrapper_task
        )
        if entry == "validate" and scope.stage == scope.mode + "_running" and original:
            scope.stage = "validating"
            return
        if entry == "validated" and scope.stage == "validating" and original:
            scope.stage = scope.mode + "_validated"
            return
        if entry == "_run" and scope.stage == "sync_validated" and scope.thread_id == thread:
            scope.stage = "native_running"
            return
        if (
            entry == "_arun_create"
            and scope.mode == "async"
            and scope.stage == "async_validated"
            and task is scope.wrapper_task
        ):
            scope.stage = "async_created"
            return scope
        if (
            entry == "_arun"
            and scope.mode == "async"
            and scope.stage == "async_created"
            and task is not None
            and task.get_coro() is scope.native_coroutine
        ):
            scope.native_task, scope.stage = task, "native_running"
            return
        raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))

    def _consume(self, proxy, *, asynchronous):
        scope = self._current.get()
        if (
            scope is None
            or not scope.active
            or scope.cancelled
            or scope.request.tool is not proxy
            or scope.stage != "native_running"
            or (
                asynchronous
                and (scope.mode != "async" or _task() is not scope.native_task)
                or not asynchronous
                and (scope.mode == "async" or get_ident() != scope.thread_id)
            )
        ):
            raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
        scope.stage = "consumed"
        return scope

    def status(self):
        connected = False
        if not self._closed and self.node is not None:
            try:
                self.sdk.context(self.session)
                for _, _, sync_tool, async_tool in self._records.values():
                    for tool in (sync_tool, async_tool):
                        if tool is not None:
                            self.sdk._tools[tool].guard()
                connected = (
                    self.node._wrap_tool_call is self._wrapper
                    and self.node._awrap_tool_call is self._awrapper
                )
            except (ValueError, AttributeError, TypeError):
                pass
        return coverage(
            "langgraph",
            installed=self.node is not None,
            connected=connected,
            synchronous=any(record[2] is not None for record in self._records.values()),
            asynchronous=any(record[3] is not None for record in self._records.values()),
        )

    def close(self):
        self._closed = True
        for task in tuple(self._native_work):
            try:
                task.get_loop().call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
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
