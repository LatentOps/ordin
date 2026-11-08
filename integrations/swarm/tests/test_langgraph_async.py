"""Actual pinned coroutine StructuredTools; no paid models or runtime networking."""

import asyncio
from contextvars import ContextVar
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_framework_conformance import host, offline, require_sdk


def call(identity, *, name="read_file", **arguments):
    from langchain_core.messages import AIMessage

    return {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": name,
                        "args": arguments,
                        "id": identity,
                    }
                ],
                additional_kwargs={"agent_id": "operator", "task_id": "foreign"},
            )
        ]
    }


def installed(tmp_path, tool_sets, *, budget=False, handle_tool_errors=True):
    require_sdk("langgraph")
    from langgraph.graph import StateGraph, MessagesState, START, END
    from ordin_swarm.adapters.langgraph import LangGraphAdapter

    graphs = [StateGraph(MessagesState) for _ in tool_sets]
    sdk, operator, sessions, events, target = host(graphs, "langgraph", tmp_path, budget=budget)
    adapters, nodes, running = [], [], []
    for graph, session, tools in zip(graphs, sessions, tool_sets):
        adapter = LangGraphAdapter(sdk, session, operator=operator)
        node = adapter.tool_node(tools, handle_tool_errors=handle_tool_errors)
        graph.add_node("tools", node)
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        adapters.append(adapter)
        nodes.append(node)
        running.append(graph.compile())
    return SimpleNamespace(
        sdk=sdk,
        operator=operator,
        sessions=sessions,
        events=events,
        target=target,
        adapters=adapters,
        nodes=nodes,
        running=running,
    )


def budget_state(world, index=0):
    row = world.sdk._sessions[world.sessions[index]]
    return row.gateway._budget.report(row.context, channel=row.channel, adapter=row.adapter)[
        "limits"
    ][0]


async def drain_until(predicate):
    for _ in range(100):
        if predicate():
            return
        await asyncio.sleep(0)
    assert predicate(), "async host lifecycle did not settle within its ready-queue bound"


def test_langgraph_async_native_coroutine_reviews_normalized_arguments(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, field_validator

    called = []

    class Args(BaseModel):
        path: str
        count: int

        @field_validator("path")
        @classmethod
        def normalize(cls, value):
            return value.strip()

    async def read_file(path: str, count: int) -> dict:
        """Read the normalized finite fixture."""
        await asyncio.sleep(0)
        called.append((path, count))
        return {"path": path, "count": count}

    original = StructuredTool.from_function(coroutine=read_file, args_schema=Args)
    world = installed(tmp_path, [[original]], budget=True)
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(
            call("native-async", path=" " + str(world.target) + " ", count="2")
        )
    )
    message = result["messages"][-1]
    assert message.status == "success"
    assert json.loads(message.content) == {"path": str(world.target), "count": 2}
    assert called == [(str(world.target), 2)]
    pending = next(iter(world.sdk._calls.values()))
    assert pending.arguments == {"path": str(world.target), "count": 2}
    assert pending.owner_task is None and pending.state == "completed"
    status = world.adapters[0].status()
    assert status["connected"] and not status["physical_enforcement"]
    assert "bound_asynchronous_tool_calls" in status["covered"]
    assert "bound_synchronous_tool_calls" not in status["covered"]
    assert "async_native_tools" not in status["uncovered"]
    assert budget_state(world)["consumed"] == 1
    assert world.events.snapshot()[-1].event.identity.agent_id == "agent0"


def test_langgraph_async_two_agents_progress_without_thread_locks_across_await(
    tmp_path, async_loop
):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    marker = ContextVar("fixture-agent-marker", default=None)
    entered = [asyncio.Event(), asyncio.Event()]
    release = asyncio.Event()
    observed = []

    def tool(index):
        async def read_file(path: str) -> str:
            """Read from one original actor."""
            observed.append((index, marker.get(), path))
            entered[index].set()
            await release.wait()
            return str(index)

        return StructuredTool.from_function(coroutine=read_file)

    world = installed(tmp_path, [[tool(0)], [tool(1)]], budget=True)

    async def run():
        async def invoke(index):
            token = marker.set(index)
            try:
                return await world.running[index].ainvoke(call("parallel", path=str(world.target)))
            finally:
                marker.reset(token)

        tasks = [asyncio.create_task(invoke(index)) for index in range(2)]
        try:
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered)), 2)
            assert budget_state(world)["reserved"] == 2
            row = world.sdk._sessions[world.sessions[0]]
            actor = row.gateway._actor(row.actor)
            locks = [
                world.sdk._lock,
                row.lock,
                row.gateway._lock,
                row.gateway._operation_lock,
                actor.lock,
                actor.gate._registry._policy_execution_barrier,
            ]

            def probe():
                for lock in locks:
                    assert lock.acquire(timeout=0.5), "thread lock remained held across await"
                    lock.release()

            await asyncio.wait_for(asyncio.to_thread(probe), 2)
        finally:
            release.set()
        results = await asyncio.gather(*tasks)
        assert [result["messages"][-1].content for result in results] == ["0", "1"]

    async_loop.run_until_complete(run())
    assert sorted(observed) == [(0, 0, str(world.target)), (1, 1, str(world.target))]
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 2
    assert {
        item.event.identity.agent_id
        for item in world.events.snapshot()
        if item.event.event_kind == "completed"
    } == {"agent0", "agent1"}


def test_langgraph_async_gate_policy_mutation_cannot_commit_an_old_completion(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from ordin.swarm import SwarmPolicy

    entered, finish = asyncio.Event(), asyncio.Event()
    called = []

    async def read_file(path: str) -> str:
        """Run a finite host callback across a host policy change."""
        called.append(path)
        entered.set()
        await finish.wait()
        return "old-policy-result"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)
    row = world.sdk._sessions[world.sessions[0]]
    actor = row.gateway._actor(row.actor)

    async def run():
        work = asyncio.create_task(world.running[0].ainvoke(call("policy", path=str(world.target))))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            actor.gate._policy = SwarmPolicy("changed", "2")
        finally:
            finish.set()
        result = await work
        assert result["messages"][-1].status == "error"
        assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
        assert row.gateway.status(row.actor)["journal_gap"]

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())


def test_langgraph_async_child_tasks_cannot_inherit_native_authority(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, field_validator
    from ordin_swarm.sdk import SwarmToolRefused

    holder, attempted, called = {}, [], []

    async def private_arun(path):
        return await holder["proxy"]._arun(path=path)

    class Args(BaseModel):
        path: str

        @field_validator("path")
        @classmethod
        def attempt_before_native_entry(cls, value):
            proxy = holder["proxy"]
            attempted.append(asyncio.create_task(proxy.coroutine(path="not-reviewed")))
            attempted.append(asyncio.create_task(proxy.ainvoke({"path": "not-reviewed"})))
            attempted.append(asyncio.create_task(proxy.arun({"path": "not-reviewed"})))
            attempted.append(asyncio.create_task(private_arun("not-reviewed")))
            # Even a synchronous invocation during schema validation cannot
            # reserve the original coroutine or enter the synchronous callback.
            with pytest.raises(SwarmToolRefused):
                proxy._arun(path="validator-not-reviewed")
            with pytest.raises(SwarmToolRefused):
                proxy._run(path="validator-not-reviewed")
            return value.strip()

    async def read_file(path: str) -> str:
        """Read only under the original native scope."""
        called.append(path)
        proxy = holder["proxy"]
        attempted.append(asyncio.create_task(proxy.coroutine(path="child-not-reviewed")))
        attempted.append(asyncio.create_task(proxy.ainvoke({"path": "child-not-reviewed"})))
        attempted.append(asyncio.create_task(proxy.arun({"path": "child-not-reviewed"})))
        attempted.append(asyncio.create_task(private_arun("child-not-reviewed")))
        return "bounded-result"

    world = installed(
        tmp_path, [[StructuredTool.from_function(coroutine=read_file, args_schema=Args)]]
    )
    holder["proxy"] = world.nodes[0].tools_by_name["read_file"]

    async def run():
        result = await world.running[0].ainvoke(call("parent", path=" " + str(world.target) + " "))
        assert result["messages"][-1].status == "success"
        outcomes = await asyncio.gather(*attempted, return_exceptions=True)
        assert len(outcomes) == 8 and all(isinstance(value, SwarmToolRefused) for value in outcomes)
        with pytest.raises(SwarmToolRefused):
            await holder["proxy"].ainvoke({"path": "direct-not-reviewed"})
        with pytest.raises(SwarmToolRefused):
            await holder["proxy"].coroutine(path="direct-not-reviewed")
        with pytest.raises(SwarmToolRefused):
            holder["proxy"]._arun(path="direct-not-reviewed")

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]


def test_langgraph_async_cancelled_callback_retains_uncertain_budget_without_late_success(
    tmp_path, async_loop
):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    entered, swallowed, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
    late = []

    async def read_file(path: str) -> str:
        """A finite fixture that deliberately suppresses its first cancellation."""
        entered.set()
        try:
            await finish.wait()
        except asyncio.CancelledError:
            swallowed.set()
            await finish.wait()
        late.append(path)
        return "late-result"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)
    row = world.sdk._sessions[world.sessions[0]]

    async def run():
        task = asyncio.create_task(
            world.running[0].ainvoke(call("cancelled", path=str(world.target)))
        )
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(swallowed.wait(), 2)
            await drain_until(lambda: next(iter(world.sdk._calls.values())).state == "uncertain")
            state = budget_state(world)
            assert state["reserved"] == 1 and state["consumed"] == 0
            assert row.gateway.status(row.actor)["journal_gap"]
            denied = await world.running[0].ainvoke(
                call("no-implicit-retry", path=str(world.target))
            )
            assert denied["messages"][-1].status == "error"
        finally:
            finish.set()
        await drain_until(lambda: not row.gateway._async_work)
        assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0

    async_loop.run_until_complete(run())
    assert late == [str(world.target)]
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())


def sdk_world(tmp_path, *, count=1):
    sdk, operator, sessions, events, target = host(
        [object() for _ in range(count)], "langgraph", tmp_path, budget=True
    )
    return SimpleNamespace(
        sdk=sdk, operator=operator, sessions=sessions, events=events, target=target
    )


def test_langgraph_async_sdk_call_is_owned_by_its_original_task_session_and_handle(
    tmp_path, async_loop
):
    from copy import copy

    world = sdk_world(tmp_path, count=2)
    called = []

    async def read(arguments):
        called.append(arguments["path"])
        await asyncio.sleep(0)
        return {"path": arguments["path"]}

    tool = world.sdk.register_async_tool(
        world.sessions[0],
        name="read_file",
        runtime="langgraph",
        callback=read,
        guard=lambda: None,
        operator=world.operator,
    )

    async def run():
        arguments = {"path": str(world.target)}
        prepared = await world.sdk.prepare_async(
            world.sessions[0], tool, arguments, request_id="owned"
        )
        assert prepared.call is not None
        arguments["path"] = "changed-outside-the-preparation"
        with pytest.raises(ValueError):
            world.sdk.forward(world.sessions[0], prepared.call)

        async def borrow():
            with pytest.raises(ValueError, match="original task"):
                await world.sdk.forward_async(world.sessions[0], prepared.call)

        await asyncio.create_task(borrow())
        with pytest.raises(ValueError):
            await world.sdk.forward_async(world.sessions[1], prepared.call)
        with pytest.raises(ValueError):
            await world.sdk.forward_async(world.sessions[0], copy(prepared.call))
        result = await world.sdk.forward_async(world.sessions[0], prepared.call)
        assert result.value == {"path": str(world.target)}
        assert world.sdk.verify_result(result, prepared.call)
        assert not world.sdk.verify_result(copy(result), prepared.call)
        assert not result.physical_enforcement
        with pytest.raises(ValueError):
            await world.sdk.forward_async(world.sessions[0], prepared.call)
        with pytest.raises(ValueError, match="already attempted"):
            await world.sdk.prepare_async(
                world.sessions[0], tool, {"path": str(world.target)}, request_id="owned"
            )

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 1


@pytest.mark.parametrize("mutation", ["arguments", "callback"])
def test_langgraph_async_pre_effect_mutation_consumes_call_without_forwarding(
    tmp_path, async_loop, mutation
):
    world = sdk_world(tmp_path)
    called = []

    async def read(arguments):
        called.append(arguments["path"])
        return "original"

    async def replacement(arguments):
        called.append("mutated")
        return "wrong"

    tool = world.sdk.register_async_tool(
        world.sessions[0],
        name="read_file",
        runtime="langgraph",
        callback=read,
        guard=lambda: None,
        operator=world.operator,
    )

    async def run():
        prepared = await world.sdk.prepare_async(
            world.sessions[0], tool, {"path": str(world.target)}, request_id="mutate"
        )
        original_code = read.__code__
        try:
            if mutation == "callback":
                read.__code__ = replacement.__code__
            with pytest.raises(ValueError, match="changed"):
                await world.sdk.forward_async(
                    world.sessions[0],
                    prepared.call,
                    arguments={"path": "changed"} if mutation == "arguments" else None,
                )
        finally:
            read.__code__ = original_code
        with pytest.raises(ValueError):
            await world.sdk.forward_async(world.sessions[0], prepared.call)

    async_loop.run_until_complete(run())
    assert called == []
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 0


def test_langgraph_async_same_actor_parallel_calls_are_serial_and_replays_refused(
    tmp_path, async_loop
):
    require_sdk("langgraph")
    from langchain_core.messages import AIMessage
    from langchain_core.tools import StructuredTool

    active = maximum = 0
    called = []

    async def read_file(path: str) -> str:
        """Read under one serial original actor."""
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        try:
            await asyncio.sleep(0)
            called.append(path)
            return path
        finally:
            active -= 1

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)

    async def run():
        message = AIMessage(
            content="",
            tool_calls=[
                {"name": "read_file", "args": {"path": str(world.target)}, "id": "one"},
                {"name": "read_file", "args": {"path": str(world.target)}, "id": "two"},
            ],
        )
        result = await world.running[0].ainvoke({"messages": [message]})
        assert [item.status for item in result["messages"][-2:]] == ["success", "success"]
        duplicate = await asyncio.gather(
            *(world.running[0].ainvoke(call("duplicate", path=str(world.target))) for _ in range(2))
        )
        assert sorted(item["messages"][-1].status for item in duplicate) == ["error", "success"]

    async_loop.run_until_complete(run())
    assert maximum == 1 and called == [str(world.target)] * 3
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 3


def test_langgraph_async_sync_and_dual_tools_keep_native_invocation_choice(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    called = []

    def read_file(path: str) -> str:
        """Read on the synchronous native route."""
        called.append(("sync", path))
        return "sync"

    async def aread_file(path: str) -> str:
        """Read on the coroutine native route."""
        await asyncio.sleep(0)
        called.append(("async", path))
        return "async"

    world = installed(tmp_path, [[StructuredTool.from_function(read_file, coroutine=aread_file)]])
    assert (
        world.running[0].invoke(call("sync", path=str(world.target)))["messages"][-1].content
        == "sync"
    )
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(call("async", path=str(world.target)))
    )
    assert result["messages"][-1].content == "async"
    assert called == [("sync", str(world.target)), ("async", str(world.target))]
    status = world.adapters[0].status()
    assert "bound_synchronous_tool_calls" in status["covered"]
    assert "bound_asynchronous_tool_calls" in status["covered"]


def test_langgraph_async_sync_tools_offload_without_gateway_locks(tmp_path, async_loop):
    require_sdk("langgraph")
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from langchain_core.tools import StructuredTool

    barrier = Barrier(2)
    called = []

    def read_file(path: str) -> str:
        """A blocking host function on the native async entry."""
        barrier.wait(timeout=2)
        called.append(path)
        return path

    world = installed(
        tmp_path,
        [[StructuredTool.from_function(read_file)], [StructuredTool.from_function(read_file)]],
        budget=True,
    )

    async def run():
        results = await asyncio.wait_for(
            asyncio.gather(
                *(
                    graph.ainvoke(call("sync-async", path=str(world.target)))
                    for graph in world.running
                )
            ),
            4,
        )
        assert all(result["messages"][-1].status == "success" for result in results)

    async_loop.run_until_complete(run())
    assert called == [str(world.target)] * 2
    assert budget_state(world)["consumed"] == 2


def test_langgraph_async_native_error_handlers_and_data_artifacts_are_preserved(
    tmp_path, async_loop
):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool, ToolException

    artifact = {"bounded": True}

    async def read_file(path: str) -> tuple:
        """Return a bounded native content/artifact pair."""
        if path == "error":
            raise ToolException("synthetic private detail")
        return "content", artifact

    original = StructuredTool.from_function(
        coroutine=read_file, response_format="content_and_artifact", handle_tool_error="safe error"
    )
    world = installed(tmp_path, [[original]], handle_tool_errors=False)

    async def run():
        success = await world.running[0].ainvoke(call("artifact", path=str(world.target)))
        message = success["messages"][-1]
        assert message.content == "content" and message.artifact == {"bounded": True}
        artifact["bounded"] = False
        assert message.artifact == {"bounded": True}
        failure = await world.running[0].ainvoke(call("native-error", path="error"))
        assert failure["messages"][-1].status == "error"
        assert failure["messages"][-1].content == "safe error"

    async_loop.run_until_complete(run())


def test_langgraph_async_unhandled_original_callback_exception_is_not_retyped(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    error = OSError("synthetic callback failure")

    async def read_file(path: str) -> str:
        """Raise the original native exception."""
        raise error

    world = installed(
        tmp_path,
        [[StructuredTool.from_function(coroutine=read_file)]],
        budget=True,
        handle_tool_errors=False,
    )

    async def run():
        with pytest.raises(OSError) as captured:
            await world.running[0].ainvoke(call("native-exception", path=str(world.target)))
        assert captured.value is error

    async_loop.run_until_complete(run())
    assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
    assert world.events.snapshot()[-1].event.event_kind == "failed"


@pytest.mark.parametrize("output", ["oversize", "command", "send", "coroutine"])
def test_langgraph_async_non_data_or_unbounded_outputs_do_not_commit_success(
    tmp_path, async_loop, output
):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from langgraph.types import Command, Send

    called = []

    async def nested():
        pytest.fail("unrepresented returned coroutine executed")

    async def read_file(path: str):
        """Return a deliberately unsupported native output."""
        called.append(path)
        if output == "oversize":
            return "x" * 65537
        if output == "command":
            return Command(goto="unrepresented")
        if output == "send":
            return Send("unrepresented", {})
        return nested()

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(call("bad-output", path=str(world.target)))
    )
    assert result["messages"][-1].status == "error"
    assert called == [str(world.target)]
    assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())


def test_langgraph_async_close_fences_inflight_and_queued_native_calls(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    entered, finish = asyncio.Event(), asyncio.Event()
    called = []

    async def read_file(path: str) -> str:
        """Wait under one original host scope."""
        called.append(path)
        entered.set()
        await finish.wait()
        return "done"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)
    row = world.sdk._sessions[world.sessions[0]]

    async def run():
        active = asyncio.create_task(
            world.running[0].ainvoke(call("active", path=str(world.target)))
        )
        queued = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            queued = asyncio.create_task(
                world.running[0].ainvoke(call("queued", path=str(world.target)))
            )
            await asyncio.sleep(0)
            world.adapters[0].close()
            results = await asyncio.wait_for(
                asyncio.gather(active, queued, return_exceptions=True), 2
            )
            assert all(
                isinstance(result, BaseException) or result["messages"][-1].status == "error"
                for result in results
            )
            await drain_until(lambda: not row.gateway._async_work)
            assert (
                row.gateway._budget.report(row.context, channel=row.channel, adapter=row.adapter)[
                    "limits"
                ][0]["reserved"]
                == 1
            )
        finally:
            finish.set()
            for task in (active, queued):
                if task is not None and not task.done():
                    task.cancel()

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())


def test_langgraph_async_midawait_callback_mutation_discards_completion(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    entered, finish = asyncio.Event(), asyncio.Event()
    called = []

    async def read_file(path: str) -> str:
        """Return only after the host mutation control."""
        entered.set()
        await finish.wait()
        called.append(path)
        return "original"

    async def mutated(path: str) -> str:
        pytest.fail("replacement callback executed")

    original = StructuredTool.from_function(coroutine=read_file)
    world = installed(tmp_path, [[original]], budget=True)

    async def run():
        task = asyncio.create_task(
            world.running[0].ainvoke(call("mutated-inflight", path=str(world.target)))
        )
        try:
            await asyncio.wait_for(entered.wait(), 2)
            original.coroutine = mutated
        finally:
            finish.set()
        result = await task
        assert result["messages"][-1].status == "error"

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())


def test_langgraph_async_inherited_background_scope_cannot_start_a_new_native_request(
    tmp_path, async_loop
):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from ordin_swarm.sdk import SwarmToolRefused

    release, holder, children, called = asyncio.Event(), {}, [], []

    async def read_file(path: str) -> str:
        """Attempt a background action only after parent completion."""
        called.append(path)

        async def background():
            await release.wait()
            return await holder["graph"].ainvoke(call("background", path=holder["target"]))

        if len(called) == 1:
            children.append(asyncio.create_task(background()))
        return "done"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]])
    holder["graph"] = world.running[0]
    holder["target"] = str(world.target)

    async def run():
        result = await world.running[0].ainvoke(call("parent-once", path=str(world.target)))
        assert result["messages"][-1].status == "success"
        release.set()
        try:
            denied = await children[0]
        except SwarmToolRefused:
            pass
        else:
            assert denied["messages"][-1].status == "error"

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert len(world.sdk._calls) == 1


@pytest.mark.parametrize("injection", ["state", "config"])
def test_langgraph_async_injected_native_routes_remain_explicitly_unsupported(tmp_path, injection):
    require_sdk("langgraph")
    from typing import Annotated
    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import StructuredTool
    from langgraph.prebuilt import InjectedState
    from langgraph.graph import StateGraph, MessagesState
    from ordin_swarm.adapters.langgraph import LangGraphAdapter

    async def with_state(path: str, state: Annotated[dict, InjectedState]) -> str:
        """Unsupported native state injection."""
        pytest.fail("injected callback executed")

    async def with_config(path: str, options: RunnableConfig) -> str:
        """Unsupported native config injection."""
        pytest.fail("injected callback executed")

    graph = StateGraph(MessagesState)
    sdk, operator, sessions, _, _ = host([graph], "langgraph", tmp_path)
    adapter = LangGraphAdapter(sdk, sessions[0], operator=operator)
    original = StructuredTool.from_function(
        coroutine=with_state if injection == "state" else with_config, name="read_file"
    )
    with pytest.raises(ValueError, match="not represented"):
        adapter.tool_node([original])


def test_langgraph_async_denied_egress_never_calls_the_coroutine(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    effects = []

    async def upload(value: str) -> str:
        """A sink that must remain uncalled under the original policy."""
        effects.append(value)
        return "sent"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=upload)]], budget=True)
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(
            call("deny-upload", name="upload", value="SYNTHETIC_PRIVATE_FRAMEWORK_VALUE")
        )
    )
    assert result["messages"][-1].status == "error"
    assert effects == []
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 0
    assert world.events.snapshot()[-1].event.event_kind == "denied"
    assert world.events.snapshot()[-1].event.identity.agent_id == "agent0"


def test_langgraph_async_removing_the_native_wrapper_cannot_forward(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    called = []

    async def read_file(path: str) -> str:
        """Read only through the original wrapper."""
        called.append(path)
        return "read"

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]])
    world.nodes[0]._awrap_tool_call = None
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(call("missing", path=str(world.target)))
    )
    assert result["messages"][-1].status == "error"
    assert called == [] and world.sdk._calls == {}
    assert not world.adapters[0].status()["connected"]


def test_langgraph_async_native_validation_errors_never_reserve_or_call(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel

    called = []

    class Args(BaseModel):
        path: str
        count: int

    async def read_file(path: str, count: int) -> str:
        """Read a finite validated input."""
        called.append((path, count))
        return path

    original = StructuredTool.from_function(
        coroutine=read_file, args_schema=Args, handle_validation_error="invalid native input"
    )
    world = installed(tmp_path, [[original]], budget=True, handle_tool_errors=False)
    result = async_loop.run_until_complete(
        world.running[0].ainvoke(
            call("invalid-native-input", path=str(world.target), count="not-an-int")
        )
    )
    assert result["messages"][-1].status == "error"
    assert result["messages"][-1].content == "invalid native input"
    assert called == [] and world.sdk._calls == {}
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 0


def test_langgraph_async_queued_cancellation_has_no_effect_or_reservation(tmp_path, async_loop):
    require_sdk("langgraph")
    from langchain_core.tools import StructuredTool

    entered, finish = asyncio.Event(), asyncio.Event()
    called = []

    async def read_file(path: str) -> str:
        """Read once while a second native request is queued."""
        called.append(path)
        entered.set()
        await finish.wait()
        return path

    world = installed(tmp_path, [[StructuredTool.from_function(coroutine=read_file)]], budget=True)

    async def run():
        first = asyncio.create_task(world.running[0].ainvoke(call("first", path=str(world.target))))
        await asyncio.wait_for(entered.wait(), 2)
        queued = asyncio.create_task(
            world.running[0].ainvoke(call("never-admitted", path=str(world.target)))
        )
        await asyncio.sleep(0)
        queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await queued
        assert len(world.sdk._calls) == 1
        assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
        finish.set()
        assert (await first)["messages"][-1].status == "success"

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert budget_state(world)["reserved"] == 0 and budget_state(world)["consumed"] == 1


def test_langgraph_async_sync_thread_cancellation_cannot_commit_a_late_result(tmp_path, async_loop):
    require_sdk("langgraph")
    from threading import Event
    from langchain_core.tools import StructuredTool

    entered, finish, done = Event(), Event(), Event()
    called = []

    def read_file(path: str) -> str:
        """A finite host callback whose thread cannot be force-killed."""
        entered.set()
        try:
            assert finish.wait(timeout=3)
            called.append(path)
            return "late"
        finally:
            done.set()

    world = installed(tmp_path, [[StructuredTool.from_function(read_file)]], budget=True)

    async def run():
        task = asyncio.create_task(
            world.running[0].ainvoke(call("sync-cancel", path=str(world.target)))
        )
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await drain_until(lambda: next(iter(world.sdk._calls.values())).state == "uncertain")
            assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0
        finally:
            finish.set()
        assert await asyncio.to_thread(done.wait, 2)
        await asyncio.sleep(0)
        assert budget_state(world)["reserved"] == 1 and budget_state(world)["consumed"] == 0

    async_loop.run_until_complete(run())
    assert called == [str(world.target)]
    assert not any(item.event.event_kind == "completed" for item in world.events.snapshot())
