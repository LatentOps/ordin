"""Synthetic local fixtures: real SDKs, typed lineage, no hosted model calls."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import socket
import tempfile
from typing import Any


@contextmanager
def offline_runtime():
    settings = {
        "CREWAI_TELEMETRY_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true",
        "LANGSMITH_TRACING": "false",
        "LANGCHAIN_TRACING_V2": "false",
        "ANONYMIZED_TELEMETRY": "false",
        "DO_NOT_TRACK": "1",
        "AUTOGEN_DISABLE_RUNTIME_TRACING": "true",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
    }
    previous = {name: os.environ.get(name) for name in settings}
    connect, create = socket.socket.connect, socket.create_connection

    def denied(*args, **kwargs):
        raise RuntimeError("local fixture forbids runtime network access")

    try:
        os.environ.update(settings)
        setattr(socket.socket, "connect", denied)
        socket.create_connection = denied
        yield
    finally:
        setattr(socket.socket, "connect", connect)
        socket.create_connection = create
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class _Host:
    def __init__(self, native, framework, workspace):
        from ordin import (
            AgentGate,
            Ordin,
            ToolResourceBinding,
            ToolSemanticRule,
            ToolSemanticsRegistry,
        )
        from ordin.assurance import HostEvidenceSource, RepositoryScope, register_instruction_origin
        from ordin.swarm import (
            ArtifactAddress,
            CoverageManifest,
            EgressSink,
            InMemoryAgentRegistry,
            MemoryArtifactStore,
            Sensitivity,
            SwarmArtifactGateway,
            SwarmAssessmentSource,
            SwarmCausalGraph,
            SwarmEvent,
            SwarmEventIngestor,
            SwarmGate,
            SwarmMessageGateway,
            SwarmPolicy,
            SwarmSourceFlow,
            SwarmToolGateway,
        )
        from ordin.swarm.messages import DESTINATION_PATH
        from .sdk import SwarmSDK
        from .data_bridge import FrameworkDataBridge

        self.operator = object()
        self.registry = InMemoryAgentRegistry("fixture-tenant", "fixture-swarm", clock=lambda: 100)
        self.events = SwarmEventIngestor(self.registry)
        self.contexts = []
        self.sources = []
        channels = []
        adapters = []
        for index in range(2):
            adapter = object()
            channel = self.registry.bind_channel(adapter, runtime_id=framework + str(index))
            context = self.registry.enroll(
                channel,
                adapter,
                agent_id="agent" + str(index),
                session_id="session" + str(index),
                task_id="fixture-task" + str(index),
                coverage=CoverageManifest("intercept"),
            )
            self.contexts.append(context)
            channels.append(channel)
            adapters.append(adapter)
            self.sources.append(
                self.events.bind_source(context, channel, adapter, source_id="data-" + str(index))
            )
        graph = SwarmCausalGraph(self.events, self.sources[0], self.contexts[0])
        self.flow = SwarmSourceFlow(
            graph,
            operator=self.operator,
            sinks=(
                EgressSink(
                    "internal",
                    "message",
                    "tool",
                    "call",
                    DESTINATION_PATH,
                    "agent1",
                    ("public", "secret"),
                ),
                EgressSink(
                    "external",
                    "network",
                    "network",
                    "jsonrpc.request",
                    ("parameters", "url"),
                    "https://fixture.invalid/rpc",
                    ("public",),
                ),
            ),
        )
        hosts = []
        for index, source in enumerate(self.sources):
            host = HostEvidenceSource(
                "agent" + str(index),
                RepositoryScope("ordin/local-framework-fixture", "synthetic-v1"),
                "b" * 64,
                0,
                "c" * 64,
                "d" * 64,
            )
            hosts.append(host)
            self.flow.bind_actor(source, self.contexts[index], host)
        self.target = workspace / "private-fixture.txt"
        self.target.write_text("SYNTHETIC_PRIVATE_FRAMEWORK_FIXTURE")
        self.target.chmod(0o600)
        value = self.target.read_text()
        self.events.ingest(
            self.sources[0],
            SwarmEvent(
                "fixture-input",
                "artifact_read",
                self.contexts[0].registry_id,
                self.contexts[0].identity,
                self.sources[0].source_id,
                1,
                100,
                evidence_class="host_authenticated",
                resource_digests=(hashlib.sha256(value.encode()).hexdigest(),),
            ),
        )
        origin = register_instruction_origin(
            hosts[0],
            origin_id="fixture-file",
            kind="repository_file",
            classification="sensitive",
            content=value,
        )
        root = self.flow.register(
            self.sources[0],
            event_id="fixture-input",
            origin=origin,
            sensitivity=Sensitivity(("secret",)),
        )
        artifacts = SwarmArtifactGateway(
            self.flow,
            backend=MemoryArtifactStore(),
            operator=self.operator,
            workspaces=("fixture",),
            clock=lambda: 100,
        )
        self.address = ArtifactAddress(
            "fixture-tenant", "fixture-swarm", "fixture", "artifacts", "private"
        )
        artifacts.write(self.sources[0], self.address, value, expected_version=0, inputs=(root,))
        self.messages = SwarmMessageGateway(self.flow, clock=lambda: 100)
        self.inboxes: list[list[Any]] = [[], []]
        peers = [
            self.messages.register(
                self.contexts[i], self.sources[i], channels[i], adapters[i], self.inboxes[i].append
            )
            for i in range(2)
        ]
        self.channel = self.messages.grant(peers[0], peers[1], sink_id="internal")
        self.sdk = SwarmSDK(operator=self.operator)
        self.bridge = FrameworkDataBridge(self.sdk, self.flow, operator=self.operator)
        self.read_data = self.received = None
        self.uploads = self.children = 0
        self.source_statuses: list[str] = []
        core = Ordin(
            tool_semantics=ToolSemanticsRegistry(
                "fixture-reads",
                "1",
                (
                    ToolSemanticRule(
                        "read",
                        "tool",
                        "read_file",
                        ("filesystem.read",),
                        runtime=framework,
                        resources=(ToolResourceBinding("path", "path"),),
                    ),
                ),
            )
        )
        authority = SwarmAssessmentSource("fixture-source-flow", clock=lambda: 100)

        def assessment(context, action, gate, options):
            uses = (
                ()
                if self.received is None
                else (
                    self.bridge.use(
                        self.sessions[1], self.received, ("parameters", "body", "params", "value")
                    ),
                )
            )
            try:
                result = self.flow.assess(
                    self.sources[1],
                    action,
                    sink_id="external",
                    uses=uses,
                    complete=self.received is not None,
                )
                self.source_statuses.append(result.status)
                return (
                    self.flow.issue_assessment(
                        self.sources[1],
                        action,
                        authority=authority,
                        policy_digest=gate.policy_digest,
                        snapshot_digest=gate.evidence_snapshot_digest(context, **options),
                        sink_id="external",
                        uses=uses,
                        complete=self.received is not None,
                    ),
                )
            except ValueError:
                from ordin._runtime_json import digest

                return (
                    authority.issue(
                        check_id="source_flow",
                        status="unknown",
                        action_digest=digest(action.as_dict()),
                        context_digest=digest(context.as_dict()),
                        policy_digest=gate.policy_digest,
                        snapshot_digest=gate.evidence_snapshot_digest(context, **options),
                    ),
                )

        gateway = SwarmToolGateway(events=self.events, clock=lambda: 100)
        self.sessions = []
        for index, obj in enumerate(native):
            gate = SwarmGate(
                self.registry,
                AgentGate(core),
                events=self.events,
                policy=SwarmPolicy("private-egress", "1", required_checks=("source_flow",))
                if index
                else None,
                assessment_source=authority if index else None,
            )
            session = self.sdk.bind(
                obj,
                self.contexts[index],
                gate,
                channels[index],
                adapters[index],
                gateway=gateway,
                identify=lambda obj=obj: obj,
                operator=self.operator,
                assessment_provider=assessment if index else None,
            )
            self.sessions.append(session)
            self.bridge.bind(
                session,
                self.sources[index],
                operator=self.operator,
                messages=self.messages,
                peer=peers[index],
                artifacts=artifacts,
            )

    def read(self, path):
        if path != str(self.target):
            raise ValueError("fixture read path changed")
        self.read_data = self.bridge.read_artifact(self.sessions[0], self.address)
        return self.bridge.value(self.sessions[0], self.read_data)

    def transfer(self):
        if self.read_data is None:
            raise ValueError("no actual private artifact read")
        self.received = self.bridge.send(
            self.sessions[0], self.sessions[1], self.channel, self.read_data
        )
        return self.bridge.value(self.sessions[1], self.received)

    def upload(self, value):
        self.uploads += 1
        raise AssertionError("private egress must not reach its callback")

    def child(self, task):
        self.children += 1
        raise AssertionError("unrepresented child creation must not reach its callback")

    @staticmethod
    def upload_action(arguments):
        from ordin import ActionEnvelope

        return ActionEnvelope(
            "network",
            "jsonrpc.request",
            {
                "url": "https://fixture.invalid/rpc",
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "send",
                    "params": {"value": arguments["value"]},
                },
            },
        )

    def report(self, framework):
        from .adapters.contracts import coverage
        from ._reports import checked

        labels = self.flow._record(
            self.bridge.use(self.sessions[1], self.received, ("parameters", "value")).handle
        ).sensitivity.labels
        kinds = [v.event.event_kind for v in self.events.snapshot()]
        return checked(
            {
                "framework": framework,
                "versions": coverage(framework)["versions"],
                "upstream_status": coverage(framework)["upstream_status"],
                "schema_version": "ordin.swarm_framework_fixture.v1",
                "trust_boundary": "host_owned_synthetic_fixture",
                "allowed_read_completed": "completed" in kinds,
                "private_handoff_delivered": len(self.inboxes[1]) == 1,
                "inherited_labels": list(labels),
                "source_flow_violated": "violated" in self.source_statuses,
                "egress_callbacks": self.uploads,
                "child_callbacks": self.children,
                "denied_reviews": kinds.count("denied"),
                "post_tool_outcome_linked": "completed" in kinds,
                "physical_enforcement": False,
                "observed_exfiltration": "unknown",
                "execution_authority": False,
            }
        )


def run(framework):
    from .adapters.contracts import require_framework_enabled

    require_framework_enabled(framework)
    with (
        offline_runtime(),
        tempfile.TemporaryDirectory(prefix="ordin-framework-fixture-") as directory,
    ):
        workspace = Path(directory)
        if framework == "langgraph":
            return _langgraph(workspace)
        if framework == "crewai":
            return _crewai(workspace)
        if framework == "autogen":
            return _autogen(workspace)
        if framework == "custom":
            return _custom(workspace)
        raise ValueError("choose an explicit pinned framework fixture")


def _langgraph(workspace):
    from langgraph.graph import StateGraph, MessagesState, START, END
    from langchain_core.messages import AIMessage
    from langchain_core.tools import StructuredTool
    from .adapters.langgraph import LangGraphAdapter

    graphs = [StateGraph(MessagesState), StateGraph(MessagesState)]
    host = _Host(graphs, "langgraph", workspace)

    def read_file(path: str) -> str:
        """Read a private fixture artifact."""
        return host.read(path)

    def upload(value: str) -> str:
        """Send bytes to the fixture external destination."""
        return host.upload(value)

    def delegate_child(task: str) -> str:
        """Request an unrepresented child runtime."""
        return host.child(task)

    adapters = [
        LangGraphAdapter(host.sdk, session, operator=host.operator) for session in host.sessions
    ]

    def first(state):
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "read_file", "args": {"path": str(host.target)}, "id": "read"}
                    ],
                )
            ]
        }

    def second(state):
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "upload", "args": {"value": host.transfer()}, "id": "upload"}
                    ],
                )
            ]
        }

    def child(state):
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "delegate_child",
                            "args": {"task": "broader authority"},
                            "id": "child",
                        }
                    ],
                )
            ]
        }

    for index, graph in enumerate(graphs):
        tools = (
            [StructuredTool.from_function(read_file)]
            if not index
            else [
                StructuredTool.from_function(upload),
                StructuredTool.from_function(delegate_child),
            ]
        )
        node = adapters[index].tool_node(tools, action_builders={"upload": host.upload_action})
        graph.add_node("plan", first if not index else second)
        graph.add_node("tools", node)
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "tools")
        if index:
            graph.add_node("child_plan", child)
            graph.add_node("child_tools", node)
            graph.add_edge("tools", "child_plan")
            graph.add_edge("child_plan", "child_tools")
            graph.add_edge("child_tools", END)
        else:
            graph.add_edge("tools", END)
    workflow = StateGraph(MessagesState)
    workflow.add_node("a", graphs[0].compile())
    workflow.add_node("b", graphs[1].compile())
    workflow.add_edge(START, "a")
    workflow.add_edge("a", "b")
    workflow.add_edge("b", END)
    try:
        workflow.compile().invoke({"messages": []})
        return host.report("langgraph")
    finally:
        for adapter in adapters:
            adapter.close()


def _crewai(workspace):
    from .adapters.contracts import require_framework_enabled

    require_framework_enabled("crewai")
    import json
    from crewai import Agent, BaseLLM, Crew, Task
    from crewai.tools import tool
    from .adapters.crewai import CrewAIAdapter

    holder: list[_Host] = []

    class FiniteLocalLLM(BaseLLM):
        def __init__(self, stage):
            super().__init__(model="ordin-local-finite-fixture", temperature=0)
            self.stage, self.step = stage, 0

        def supports_function_calling(self):
            return False

        def get_context_window_size(self):
            return 8192

        def call(self, messages, tools=None, callbacks=None, available_functions=None, **kwargs):
            host = holder[0]
            self.step += 1
            if self.stage == 0:
                if self.step == 1:
                    return "Thought: read.\nAction: read_file\nAction Input: " + json.dumps(
                        {"path": str(host.target)}
                    )
                return "Thought: done.\nFinal Answer: collected private fixture"
            if self.step == 1:
                return "Thought: send.\nAction: upload\nAction Input: " + json.dumps(
                    {"value": host.bridge.value(host.sessions[1], host.received)}
                )
            if self.step == 2:
                return (
                    "Thought: request child.\nAction: delegate_child\nAction Input: "
                    + json.dumps({"task": "broader authority"})
                )
            return "Thought: stopped.\nFinal Answer: denied"

    agents = [
        Agent(
            role="reader",
            goal="collect fixture",
            backstory="local fixture",
            cache=False,
            allow_delegation=False,
            max_iter=6,
            max_retry_limit=0,
            llm=FiniteLocalLLM(0),
        ),
        Agent(
            role="consumer",
            goal="handle fixture",
            backstory="local fixture",
            cache=False,
            allow_delegation=False,
            max_iter=6,
            max_retry_limit=0,
            llm=FiniteLocalLLM(1),
        ),
    ]
    host = _Host(agents, "crewai", workspace)
    holder.append(host)

    @tool("read_file")
    def read_file(path: str) -> str:
        """Read a private fixture artifact."""
        return host.read(path)

    @tool("upload")
    def upload(value: str) -> str:
        """Send bytes to the fixture external destination."""
        return host.upload(value)

    @tool("delegate_child")
    def delegate_child(task: str) -> str:
        """Request an unrepresented child runtime."""
        return host.child(task)

    tasks = [
        Task(
            description="Collect the private local fixture",
            expected_output="collected",
            agent=agents[0],
            callback=lambda _: host.transfer(),
        ),
        Task(
            description="Process the collected fixture", expected_output="denied", agent=agents[1]
        ),
    ]
    tasks[1].context = [tasks[0]]
    adapters = [
        CrewAIAdapter(host.sdk, session, operator=host.operator) for session in host.sessions
    ]
    try:
        adapters[0].install(agents[0], tasks[0], [read_file])
        adapters[1].install(
            agents[1],
            tasks[1],
            [upload, delegate_child],
            action_builders={"upload": host.upload_action},
        )
        Crew(agents=agents, tasks=tasks, cache=False, memory=False, verbose=False).kickoff()
        return host.report("crewai")
    finally:
        for adapter in adapters:
            adapter.close()


def _custom(workspace):
    from .sdk import SwarmToolRefused

    class PythonAgent:
        def __init__(self):
            self.sequence = 0
            self.sdk: Any = None
            self.session: Any = None

        def call(self, tool, arguments):
            self.sequence += 1
            return self.sdk.invoke(
                self.session, tool, arguments, request_id="python-" + str(self.sequence)
            )

    agents = [PythonAgent(), PythonAgent()]
    host = _Host(agents, "custom", workspace)
    for agent, session in zip(agents, host.sessions):
        agent.sdk, agent.session = host.sdk, session
    reader = host.sdk.register_tool(
        host.sessions[0],
        name="read_file",
        runtime="custom",
        callback=lambda args: host.read(args["path"]),
        guard=lambda: None,
        operator=host.operator,
    )
    upload = host.sdk.register_tool(
        host.sessions[1],
        name="upload",
        runtime="custom",
        callback=lambda args: host.upload(args["value"]),
        guard=lambda: None,
        action_builder=host.upload_action,
        operator=host.operator,
    )
    child = host.sdk.register_tool(
        host.sessions[1],
        name="delegate_child",
        runtime="custom",
        callback=lambda args: host.child(args["task"]),
        guard=lambda: None,
        operator=host.operator,
    )
    try:
        agents[0].call(reader, {"path": str(host.target)})
        value = host.transfer()
        for tool, args, request in (
            (upload, {"value": value}, "upload"),
            (child, {"task": "broader authority"}, "child"),
        ):
            try:
                agents[1].call(tool, args)
            except SwarmToolRefused:
                pass
            else:
                raise AssertionError("fixture restriction did not deny")
        return host.report("custom")
    finally:
        for session in host.sessions:
            host.sdk.close(session)


def _autogen(workspace):
    import asyncio
    import json
    from dataclasses import dataclass
    from autogen_core import AgentId, FunctionCall, MessageContext, RoutedAgent, message_handler
    from autogen_core.tool_agent import ToolAgent, ToolException
    from .adapters.autogen import AutoGenAdapter

    adapter = AutoGenAdapter()
    host = _Host([adapter.runtime, adapter.runtime], "autogen", workspace)
    producers = [AgentId("producer0", "default"), AgentId("producer1", "default")]
    recipients = [AgentId("tools0", "default"), AgentId("tools1", "default")]
    for index in range(2):
        adapter.bind(
            host.sdk,
            host.sessions[index],
            producer=producers[index],
            recipient=recipients[index],
            operator=host.operator,
        )

    def read_file(path: str) -> str:
        return host.read(path)

    def upload(value: str) -> str:
        return host.upload(value)

    def delegate_child(task: str) -> str:
        return host.child(task)

    tools = [
        [
            adapter.function_tool(
                recipients[0], read_file, name="read_file", description="Read private fixture"
            )
        ],
        [
            adapter.function_tool(
                recipients[1],
                upload,
                name="upload",
                description="Send private fixture",
                action_builder=host.upload_action,
            ),
            adapter.function_tool(
                recipients[1],
                delegate_child,
                name="delegate_child",
                description="Request child runtime",
            ),
        ],
    ]

    @dataclass
    class Request:
        value: str

    @dataclass
    class Reply:
        denied: int

    class Producer(RoutedAgent):
        def __init__(self, index):
            super().__init__("local fixture agent")
            self.index = index

        @message_handler
        async def handle(self, message: Request, ctx: MessageContext) -> Reply:
            selected = (
                [("read_file", {"path": str(host.target)}, "read")]
                if self.index == 0
                else [
                    ("upload", {"value": message.value}, "upload"),
                    ("delegate_child", {"task": "broader authority"}, "child"),
                ]
            )
            denied = 0
            for name, arguments, reference in selected:
                try:
                    await self.send_message(
                        FunctionCall(id=reference, name=name, arguments=json.dumps(arguments)),
                        recipients[self.index],
                    )
                except ToolException:
                    denied += 1
            return Reply(denied)

    async def execute():
        for index in range(2):
            await ToolAgent.register(
                adapter.runtime,
                "tools" + str(index),
                lambda index=index: ToolAgent("fixture native tools", tools[index]),
            )
            await Producer.register(
                adapter.runtime, "producer" + str(index), lambda index=index: Producer(index)
            )
        adapter.start()
        try:
            first = await asyncio.wait_for(
                adapter.runtime.send_message(Request(""), producers[0]), 10
            )
            if first.denied:
                raise ValueError("allowed fixture read was denied")
            value = host.transfer()
            second = await asyncio.wait_for(
                adapter.runtime.send_message(Request(value), producers[1]), 10
            )
            if second.denied != 2:
                raise ValueError("fixture egress or child creation was not denied")
            return host.report("autogen")
        finally:
            await asyncio.wait_for(adapter.stop(), 10)

    return asyncio.run(execute())
