"""Adversarial controls at actual pinned SDK tool and lifecycle boundaries."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from test_framework_conformance import host, offline, require_sdk


def test_langgraph_real_normalization_replay_concurrency_callback_error_and_missing_wrapper(
    tmp_path,
):
    require_sdk("langgraph")
    from langgraph.graph import StateGraph, MessagesState, START, END
    from langchain_core.messages import AIMessage
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, field_validator
    from ordin_swarm.adapters.langgraph import LangGraphAdapter
    from ordin_swarm.sdk import SwarmToolRefused

    graph = StateGraph(MessagesState)
    sdk, operator, sessions, events, target = host([graph], "langgraph", tmp_path)
    called = []

    def read_file(path: str) -> str:
        """Read an exact local fixture."""
        called.append(path)
        if len(called) == 2:
            raise OSError("private upstream callback error")
        return Path(path).read_text()

    class Args(BaseModel):
        path: str

        @field_validator("path")
        @classmethod
        def normalize(cls, value):
            return value.strip()

    original = StructuredTool.from_function(read_file, args_schema=Args)
    adapter = LangGraphAdapter(sdk, sessions[0], operator=operator)
    node = adapter.tool_node([original])
    graph.add_node("tools", node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    running = graph.compile()
    call = {
        "name": "read_file",
        "args": {"path": " " + str(target) + " "},
        "id": "same",
        "type": "tool_call",
    }

    def invoke(_):
        return running.invoke({"messages": [AIMessage(content="", tool_calls=[call])]})["messages"][
            -1
        ]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(invoke, range(2)))
    assert sorted(v.status for v in results) == ["error", "success"] and called == [str(target)]
    stored = next(iter(sdk._calls.values()))
    assert stored.arguments == {"path": str(target)}
    failed = running.invoke(
        {"messages": [AIMessage(content="", tool_calls=[{**call, "id": "fails"}])]}
    )["messages"][-1]
    assert failed.status == "error" and events.snapshot()[-1].event.event_kind == "failed"
    assert "private upstream" not in json.dumps([v.event.as_dict() for v in events.snapshot()])
    original.func = lambda path: pytest.fail("changed callback executed")
    try:
        changed = running.invoke(
            {"messages": [AIMessage(content="", tool_calls=[{**call, "id": "mutated"}])]}
        )
        assert changed["messages"][-1].status == "error"
    except ValueError:
        pass
    assert len(called) == 2
    node._wrap_tool_call = None
    missing = running.invoke(
        {"messages": [AIMessage(content="", tool_calls=[{**call, "id": "missing"}])]}
    )["messages"][-1]
    assert missing.status == "error" and len(called) == 2
    asynchronous = asyncio.run(
        running.ainvoke({"messages": [AIMessage(content="", tool_calls=[{**call, "id": "async"}])]})
    )
    assert asynchronous["messages"][-1].status == "error" and len(called) == 2
    assert adapter.plan_existing(node)["restart_required"]


def test_crewai_real_dispatch_hook_scope_cannot_be_spoofed_replayed_or_bypassed(tmp_path):
    require_sdk("crewai")
    from crewai import Agent, Task, BaseLLM
    from crewai.tools import tool
    from crewai.hooks import (
        ToolCallHookContext,
        unregister_before_tool_call_hook,
    )
    from crewai.hooks.tool_hooks import run_before_tool_call_hooks
    from ordin_swarm.adapters.crewai import CrewAIAdapter
    from ordin_swarm.sdk import SwarmToolRefused

    class LocalLLM(BaseLLM):
        def __init__(self):
            super().__init__(model="offline-fixture")

        def call(self, *args, **kwargs):
            raise AssertionError("hook control uses no model")

    agents = [
        Agent(role="same-role", goal="fixture", backstory="fixture", llm=LocalLLM(), cache=False)
        for _ in range(2)
    ]
    tasks = [Task(description="fixture", expected_output="result", agent=agent) for agent in agents]
    sdk, operator, sessions, events, target = host(agents, "crewai", tmp_path)
    called = []

    @tool("read_file")
    def read_file(path: str) -> str:
        """Read the local fixture."""
        called.append(path)
        return Path(path).read_text()

    adapter = CrewAIAdapter(sdk, sessions[0], operator=operator)
    guarded = adapter.install(agents[0], tasks[0], [read_file])[0]
    native = guarded.to_structured_tool()
    args = {"path": str(target)}
    try:
        spoofed = ToolCallHookContext(
            "read_file", dict(args), native, agent=agents[1], task=tasks[1]
        )
        run_before_tool_call_hooks(spoofed)
        with pytest.raises(SwarmToolRefused):
            native.invoke(args)
        assert not called
        correct = ToolCallHookContext(
            "read_file", dict(args), native, agent=agents[0], task=tasks[0]
        )
        assert not run_before_tool_call_hooks(correct)
        assert run_before_tool_call_hooks(correct)
        assert native.invoke(args) == target.read_text()
        with pytest.raises(SwarmToolRefused):
            native.invoke(args)
        assert len(called) == 1
        unregister_before_tool_call_hook(adapter._before_hook)
        with pytest.raises(SwarmToolRefused):
            native.invoke(args)
        assert not adapter.status()["connected"]
        assert events.snapshot()[-1].event.event_kind == "completed"
    finally:
        adapter.close()
    agents[1].cache = True
    refused = CrewAIAdapter(sdk, sessions[1], operator=operator)
    original = agents[1].tools
    with pytest.raises(ValueError):
        refused.install(agents[1], tasks[1], [read_file])
    assert agents[1].tools is original


def test_archived_autogen_real_runtime_rejects_wrong_sender_and_direct_tool_calls(tmp_path):
    require_sdk("autogen")
    from autogen_core import AgentId, FunctionCall, CancellationToken, RoutedAgent
    from autogen_core.tool_agent import ToolAgent, ToolException
    from ordin_swarm.adapters.autogen import AutoGenAdapter
    from ordin_swarm.sdk import SwarmToolRefused

    adapter = AutoGenAdapter()
    sdk, operator, sessions, events, target = host([adapter.runtime], "autogen", tmp_path)
    producer, recipient = AgentId("producer", "default"), AgentId("tools", "default")
    adapter.bind(sdk, sessions[0], producer=producer, recipient=recipient, operator=operator)
    called = []

    def read_file(path: str) -> str:
        called.append(path)
        return Path(path).read_text()

    native = adapter.function_tool(
        recipient, read_file, name="read_file", description="Read fixture"
    )

    async def run():
        await RoutedAgent.register(
            adapter.runtime, "producer", lambda: RoutedAgent("host-owned producer")
        )
        await ToolAgent.register(
            adapter.runtime, "tools", lambda: ToolAgent("local tools", [native])
        )
        adapter.start()
        try:
            with pytest.raises(SwarmToolRefused):
                await native.run_json({"path": str(target)}, CancellationToken())
            with pytest.raises(ToolException):
                await asyncio.wait_for(
                    adapter.runtime.send_message(
                        FunctionCall(
                            id="spoof",
                            name="read_file",
                            arguments=json.dumps({"path": str(target)}),
                        ),
                        recipient,
                        sender=AgentId("operator", "default"),
                    ),
                    10,
                )
            assert not called
            result = await asyncio.wait_for(
                adapter.runtime.send_message(
                    FunctionCall(
                        id="ok", name="read_file", arguments=json.dumps({"path": str(target)})
                    ),
                    recipient,
                    sender=producer,
                ),
                10,
            )
            assert result.content == target.read_text() and len(called) == 1
            native._func = lambda path: pytest.fail("mutated callback executed")
            with pytest.raises(ToolException):
                await asyncio.wait_for(
                    adapter.runtime.send_message(
                        FunctionCall(
                            id="changed",
                            name="read_file",
                            arguments=json.dumps({"path": str(target)}),
                        ),
                        recipient,
                        sender=producer,
                    ),
                    10,
                )
        finally:
            await asyncio.wait_for(adapter.stop(), 10)

    asyncio.run(run())
    assert events.snapshot()[-1].event.event_kind == "completed"
