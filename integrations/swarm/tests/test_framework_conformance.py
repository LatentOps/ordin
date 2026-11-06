"""Real pinned SDK lifecycles and local tools; no paid/model/provider transport."""

from pathlib import Path
import json
import socket
import importlib
import os

import pytest


def require_sdk(framework):
    module = {"langgraph": "langgraph", "crewai": "crewai", "autogen": "autogen_core"}[framework]
    if os.environ.get("ORDIN_REQUIRED_FRAMEWORK") == framework:
        return importlib.import_module(module)
    return pytest.importorskip(module)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    for name, value in {
        "CREWAI_TELEMETRY_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true",
        "ANONYMIZED_TELEMETRY": "false",
        "LANGSMITH_TRACING": "false",
        "LANGCHAIN_TRACING_V2": "false",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "DO_NOT_TRACK": "1",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LANGSMITH_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def denied(*args, **kwargs):
        raise AssertionError("fixture attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def host(native, runtime, tmp_path):
    from ordin import AgentGate, Ordin, ToolSemanticsRegistry, ToolSemanticRule, ToolResourceBinding
    from ordin.swarm import (
        InMemoryAgentRegistry,
        SwarmEventIngestor,
        SwarmGate,
        SwarmPolicy,
        SwarmRule,
        CoverageManifest,
        SwarmToolGateway,
    )
    from ordin_swarm.sdk import SwarmSDK

    operator = object()
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: 100)
    events = SwarmEventIngestor(registry)
    core = Ordin(
        tool_semantics=ToolSemanticsRegistry(
            "framework-local",
            "1",
            (
                ToolSemanticRule(
                    "read",
                    "tool",
                    "read_file",
                    ("filesystem.read",),
                    runtime=runtime,
                    resources=(ToolResourceBinding("path", "path"),),
                ),
                ToolSemanticRule("upload", "tool", "upload", ("network.upload",), runtime=runtime),
            ),
        )
    )
    gate = SwarmGate(
        registry,
        AgentGate(core),
        events=events,
        policy=SwarmPolicy(
            "stop-egress", "1", rules=(SwarmRule("no-upload", "deny", effects=("network.upload",)),)
        ),
    )
    sdk = SwarmSDK(operator=operator)
    gateway = SwarmToolGateway(events=events, clock=lambda: 100)
    sessions = []
    for index, obj in enumerate(native):
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id=runtime + str(index))
        context = registry.enroll(
            channel,
            adapter,
            agent_id="agent" + str(index),
            session_id="session" + str(index),
            task_id="task" + str(index),
            coverage=CoverageManifest("intercept"),
        )
        sessions.append(
            sdk.bind(
                obj,
                context,
                gate,
                channel,
                adapter,
                gateway=gateway,
                identify=lambda obj=obj: obj,
                operator=operator,
            )
        )
    target = tmp_path / "secret.txt"
    target.write_text("SYNTHETIC_PRIVATE_FRAMEWORK_VALUE")
    return sdk, operator, sessions, events, target


def test_real_langgraph_two_agent_workflow_benign_read_and_cross_agent_egress_denial(tmp_path):
    require_sdk("langgraph")
    from langgraph.graph import StateGraph, MessagesState, START, END
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import StructuredTool
    from ordin_swarm.adapters.langgraph import LangGraphAdapter

    graphs = [StateGraph(MessagesState), StateGraph(MessagesState)]
    sdk, operator, sessions, events, target = host(graphs, "langgraph", tmp_path)
    uploads = []

    def read_file(path: str) -> str:
        """Read the exact local fixture file."""
        return Path(path).read_text()

    def upload(value: str) -> str:
        """Send data to the fixture external sink."""
        uploads.append(value)
        return "sent"

    adapters = [LangGraphAdapter(sdk, session, operator=operator) for session in sessions]
    tools = [StructuredTool.from_function(read_file), StructuredTool.from_function(upload)]

    def propose_a(state):
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "read_file", "args": {"path": str(target)}, "id": "read-a"}
                    ],
                    additional_kwargs={"agent_id": "operator"},
                )
            ]
        }

    def propose_b(state):
        result = next(v for v in reversed(state["messages"]) if isinstance(v, ToolMessage))
        assert result.content == target.read_text()
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "upload", "args": {"value": result.content}, "id": "upload-b"}
                    ],
                    additional_kwargs={"agent_id": "agent0", "task_id": "operator"},
                )
            ]
        }

    for graph, adapter, tool, proposer in zip(graphs, adapters, tools, (propose_a, propose_b)):
        graph.add_node("propose", proposer)
        graph.add_node("tools", adapter.tool_node([tool]))
        graph.add_edge(START, "propose")
        graph.add_edge("propose", "tools")
        graph.add_edge("tools", END)
    workflow = StateGraph(MessagesState)
    workflow.add_node("a", graphs[0].compile())
    workflow.add_node("b", graphs[1].compile())
    workflow.add_edge(START, "a")
    workflow.add_edge("a", "b")
    workflow.add_edge("b", END)
    result = workflow.compile().invoke({"messages": []})
    assert result["messages"][-1].status == "error" and not uploads
    records = events.snapshot()
    assert any(
        v.event.event_kind == "completed" and v.event.identity.agent_id == "agent0" for v in records
    )
    assert any(
        v.event.event_kind == "denied" and v.event.identity.agent_id == "agent1" for v in records
    )
    assert all(
        adapter.status()["connected"] and not adapter.status()["physical_enforcement"]
        for adapter in adapters
    )


def test_real_crewai_two_agent_local_llm_hooks_and_exact_task_identity(tmp_path):
    require_sdk("crewai")
    from crewai import Agent, Task, Crew, BaseLLM
    from crewai.tools import tool as crew_tool
    from ordin_swarm.adapters.crewai import CrewAIAdapter

    class FiniteLocalLLM(BaseLLM):
        def __init__(self, responses):
            super().__init__(model="ordin-local-finite-fixture", temperature=0)
            self.responses = iter(responses)

        def call(self, messages, tools=None, callbacks=None, available_functions=None, **kwargs):
            return next(self.responses)

        def supports_function_calling(self):
            return False

        def get_context_window_size(self):
            return 8192

    target = tmp_path / "secret.txt"
    secret = "SYNTHETIC_PRIVATE_FRAMEWORK_VALUE"
    agents = [
        Agent(
            role="reader",
            goal="read fixture",
            backstory="local fixture",
            cache=False,
            allow_delegation=False,
            max_iter=4,
            max_retry_limit=0,
            llm=FiniteLocalLLM(
                [
                    "Thought: read.\nAction: read_file\nAction Input: "
                    + json.dumps({"path": str(target)}),
                    "Thought: done.\nFinal Answer: " + secret,
                ]
            ),
        ),
        Agent(
            role="consumer",
            goal="process fixture",
            backstory="local fixture",
            cache=False,
            allow_delegation=False,
            max_iter=4,
            max_retry_limit=0,
            llm=FiniteLocalLLM(
                [
                    "Thought: upload.\nAction: upload\nAction Input: "
                    + json.dumps({"value": secret}),
                    "Thought: stopped.\nFinal Answer: blocked",
                ]
            ),
        ),
    ]
    tasks = [
        Task(
            description="Read the local fixture", expected_output="fixture content", agent=agents[0]
        ),
        Task(
            description="Process the prior result",
            expected_output="blocked upload",
            agent=agents[1],
        ),
    ]
    tasks[1].context = [tasks[0]]
    sdk, operator, sessions, events, target = host(agents, "crewai", tmp_path)
    uploads = []

    def read_file(path: str) -> str:
        """Read the exact local fixture file."""
        return Path(path).read_text()

    def upload(value: str) -> str:
        """Send data to the fixture external sink."""
        uploads.append(value)
        return "sent"

    tools = [
        crew_tool("read_file")(read_file),
        crew_tool("upload")(upload),
    ]
    adapters = [CrewAIAdapter(sdk, session, operator=operator) for session in sessions]
    hook_diagnostics = []
    for index, adapter in enumerate(adapters):
        original = adapter._before_hook

        def observed(context, index=index, adapter=adapter, original=original):
            row = {
                "agent": context.agent is agents[index],
                "task": context.task is tasks[index],
                "original_tool_known": id(getattr(context.tool, "_original_tool", None))
                in adapter._records,
                "same_tool_list": adapter.agent.tools is adapter._wrapped,
            }
            row["blocked"] = original(context)
            hook_diagnostics.append(row)
            return row["blocked"]

        adapter._before_hook = observed
    try:
        for adapter, agent, task, tool in zip(adapters, agents, tasks, tools):
            adapter.install(agent, task, [tool])
        result = Crew(
            agents=agents, tasks=tasks, cache=False, memory=False, verbose=False
        ).kickoff()
        assert "blocked" in result.raw and not uploads
        records = events.snapshot()
        assert any(
            v.event.event_kind == "completed" and v.event.identity.agent_id == "agent0"
            for v in records
        ), hook_diagnostics
        assert any(
            v.event.event_kind == "denied" and v.event.identity.agent_id == "agent1"
            for v in records
        )
        assert all(adapter.status()["connected"] for adapter in adapters)
    finally:
        for adapter in adapters:
            adapter.close()


def test_real_archived_autogen_two_native_agents_scoped_tool_messages_and_replay(tmp_path):
    require_sdk("autogen")
    import asyncio
    from dataclasses import dataclass
    from autogen_core import AgentId, FunctionCall, MessageContext, RoutedAgent, message_handler
    from autogen_core.tool_agent import ToolAgent, ToolException
    from ordin_swarm.adapters.autogen import AutoGenAdapter

    controller = AutoGenAdapter()
    sdk, operator, sessions, events, target = host(
        [controller.runtime, controller.runtime], "autogen", tmp_path
    )
    uploads = []

    def read_file(path: str) -> str:
        return Path(path).read_text()

    def upload(value: str) -> str:
        uploads.append(value)
        return "sent"

    recipients = [AgentId("tools0", "default"), AgentId("tools1", "default")]
    producers = [AgentId("producer0", "default"), AgentId("producer1", "default")]
    for session, producer, recipient in zip(sessions, producers, recipients):
        controller.bind(sdk, session, producer=producer, recipient=recipient, operator=operator)
    tools = [
        controller.function_tool(
            recipients[0], read_file, name="read_file", description="Read local fixture"
        ),
        controller.function_tool(recipients[1], upload, name="upload", description="Send fixture"),
    ]

    @dataclass
    class Request:
        call_id: str
        arguments: dict
        claimed_role: str = "operator"

    @dataclass
    class Reply:
        text: str

    class Producer(RoutedAgent):
        def __init__(self, recipient, name):
            super().__init__("real local fixture agent")
            self.recipient, self.name = recipient, name

        @message_handler
        async def handle(self, message: Request, ctx: MessageContext) -> Reply:
            try:
                result = await self.send_message(
                    FunctionCall(
                        id=message.call_id, name=self.name, arguments=json.dumps(message.arguments)
                    ),
                    self.recipient,
                )
                return Reply(result.content)
            except ToolException:
                return Reply("blocked")

    async def run():
        for index, tool in enumerate(tools):
            await ToolAgent.register(
                controller.runtime,
                "tools" + str(index),
                lambda tool=tool: ToolAgent("native fixture tools", [tool]),
            )
            await Producer.register(
                controller.runtime,
                "producer" + str(index),
                lambda index=index: Producer(
                    recipients[index], "read_file" if index == 0 else "upload"
                ),
            )
        controller.start()
        try:
            first = await controller.runtime.send_message(
                Request("read-a", {"path": str(target)}), producers[0]
            )
            assert first.text == target.read_text()
            second = await controller.runtime.send_message(
                Request("upload-b", {"value": first.text}), producers[1]
            )
            assert second.text == "blocked" and not uploads
            replay = await controller.runtime.send_message(
                Request("read-a", {"path": str(target)}), producers[0]
            )
            assert replay.text == "blocked"
            assert (
                controller.status()["upstream_status"] == "archived"
                and controller.status()["connected"]
            )
        finally:
            await controller.stop()

    asyncio.run(run())
    assert any(
        v.event.event_kind == "completed" and v.event.identity.agent_id == "agent0"
        for v in events.snapshot()
    )
    assert any(
        v.event.event_kind == "denied" and v.event.identity.agent_id == "agent1"
        for v in events.snapshot()
    )
