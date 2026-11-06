"""CrewAI's real before-tool hook plus an independent guarded tool boundary."""

import inspect
from threading import RLock
from typing import Any
from uuid import uuid4

from ordin._runtime_json import digest
from ordin_swarm.sdk import SwarmSDK, SwarmToolRefused, bounded_json, callback_binding
from .contracts import coverage, require_version


class CrewAIAdapter:
    def __init__(self, sdk: SwarmSDK, session, *, operator: object):
        require_version("crewai")
        if type(sdk) is not SwarmSDK or operator is not sdk._operator:
            raise ValueError("original SDK operator required")
        sdk.context(session)
        self.sdk, self.session, self._operator = sdk, session, operator
        self.agent: Any = None
        self.task: Any = None
        self._closed = False
        self._scopes: dict[int, tuple] = {}
        self._scope_lock = RLock()
        self._records: dict[int, tuple] = {}
        self._before_hook = self._before
        self._after_hook = self._after
        self._previous: Any = None
        self._wrapped: Any = None
        self._installing = False

    def install(self, agent, task, tools, *, action_builders=None):
        require_version("crewai")
        from crewai import Agent, Task
        from crewai.tools import BaseTool
        from crewai.tools.base_tool import Tool
        from crewai.hooks import register_before_tool_call_hook, register_after_tool_call_hook

        if (
            self.agent is not None
            or type(agent) is not Agent
            or type(task) is not Task
            or task.agent is not agent
            or self.sdk._session(self.session).runtime is not agent
        ):
            raise ValueError("exact original CrewAI agent/task lifecycle binding required")
        if agent.cache or agent.agent_executor is not None:
            raise ValueError(
                "CrewAI cache must be explicitly disabled and executor rebuilt before install"
            )
        if (
            type(tools) not in {tuple, list}
            or not 1 <= len(tools) <= 256
            or len({v.name for v in tools}) != len(tools)
        ):
            raise ValueError("bounded unique original CrewAI tools required")
        if any(type(v) is not Tool or inspect.iscoroutinefunction(v.func) for v in tools):
            raise ValueError("only pinned synchronous native CrewAI Tool callables are represented")
        if any(
            set(inspect.signature(v.func).parameters) != set(v.args_schema.model_fields)
            for v in tools
        ):
            raise ValueError("native CrewAI schema must represent every callback argument")
        self.agent, self.task, self._previous = agent, task, agent.tools
        self._installing = True
        adapter = self
        wrapped = []
        for original in tools:
            function = original.func
            key = (
                original.name,
                callback_binding(function),
                digest(bounded_json(original.args_schema.model_json_schema())),
            )

            class GuardedTool(BaseTool):
                def _run(self, **arguments):
                    return adapter._invoke(self, arguments)

                async def _arun(self, **arguments):
                    raise SwarmToolRefused("deny", ("framework.native_async_route_unavailable",))

            tool = GuardedTool(
                name=original.name,
                description=original.description,
                args_schema=original.args_schema,
                result_schema=original.result_schema,
                result_as_answer=original.result_as_answer,
                max_usage_count=original.max_usage_count,
                current_usage_count=original.current_usage_count,
                cache_function=lambda *_: False,
            )

            def guard(original=original, key=key, tool=tool):
                require_version("crewai")
                if (
                    adapter._closed
                    or (
                        not adapter._installing
                        and (
                            adapter.agent.tools is not adapter._wrapped
                            or not any(v is tool for v in adapter._wrapped)
                        )
                    )
                    or original.name != key[0]
                    or callback_binding(original.func) != key[1]
                    or digest(bounded_json(original.args_schema.model_json_schema())) != key[2]
                    or adapter.agent.cache
                ):
                    raise ValueError("original CrewAI tool installation changed")

            def invoke(arguments, function=function):
                return function(**arguments)

            handle = self.sdk.register_tool(
                self.session,
                name=tool.name,
                runtime="crewai",
                callback=invoke,
                guard=guard,
                action_builder=(action_builders or {}).get(tool.name),
                operator=self._operator,
            )
            self._records[id(tool)] = (tool, handle, guard, type(tool)._run)
            wrapped.append(tool)
        self._wrapped = wrapped
        agent.tools = wrapped
        self._wrapped = agent.tools
        self._installing = False
        register_before_tool_call_hook(self._before_hook)
        register_after_tool_call_hook(self._after_hook)
        return tuple(self._wrapped)

    def _before(self, context):
        require_version("crewai")
        from crewai.hooks import ToolCallHookContext

        if type(context) is not ToolCallHookContext:
            return False
        if context.agent is not self.agent:
            return None
        try:
            if self._closed or context.task is not self.task:
                return False
            original: Any = getattr(context.tool, "_original_tool", None)
            if original is None:
                return False
            row = self._records.get(id(original))
            if row is None or row[0] is not original or context.tool_name != original.name:
                return False
            if (
                getattr(context.tool.func, "__self__", None) is not original
                or getattr(context.tool.func, "__func__", None) is not row[3]
            ):
                return False
            row[2]()
            normalized = bounded_json(
                row[0].args_schema.model_validate(context.tool_input).model_dump()
            )
            with self._scope_lock:
                if id(original) in self._scopes:
                    return False
                self._scopes[id(original)] = (original, uuid4().hex, digest(normalized))
            return None
        except Exception:
            return False

    def _invoke(self, tool, arguments):
        with self._scope_lock:
            current = self._scopes.pop(id(tool), None)
            row = self._records.get(id(tool))
            if (
                current is None
                or row is None
                or current[0] is not tool
                or current[2] != digest(bounded_json(arguments))
            ):
                raise SwarmToolRefused("deny", ("framework.native_scope_unverified",))
        row[2]()
        return self.sdk.invoke(self.session, row[1], arguments, request_id=current[1])

    def _after(self, context):
        return None

    def status(self):
        report = coverage("crewai")
        if report["availability"] == "security_blocked":
            return report
        from crewai.hooks import get_before_tool_call_hooks, get_after_tool_call_hooks

        connected = (
            not self._closed
            and self.agent is not None
            and self.agent.tools is self._wrapped
            and any(v is self._before_hook for v in get_before_tool_call_hooks())
            and any(v is self._after_hook for v in get_after_tool_call_hooks())
        )
        if connected:
            try:
                self.sdk.context(self.session)
                for row in self._records.values():
                    row[2]()
            except ValueError:
                connected = False
        return coverage("crewai", installed=self.agent is not None, connected=connected)

    def close(self):
        require_version("crewai")
        from crewai.hooks import unregister_before_tool_call_hook, unregister_after_tool_call_hook

        self._closed = True
        unregister_before_tool_call_hook(self._before_hook)
        unregister_after_tool_call_hook(self._after_hook)
        self.sdk.close(self.session)
        if (
            self.agent is not None
            and self.agent.tools is self._wrapped
            and self.agent.agent_executor is None
        ):
            self.agent.tools = self._previous

    @staticmethod
    def plan_existing(agent):
        return {
            "supported": getattr(agent, "agent_executor", None) is None
            and not getattr(agent, "cache", True),
            "restart_required": getattr(agent, "agent_executor", None) is not None,
            "reason_code": "framework.explicit_cache_disable_and_guarded_tool_install_required",
            "execution_authority": False,
        }


__all__ = ["CrewAIAdapter"]
