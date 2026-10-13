"""Late/canceled providers cannot outlive their deadline or recycle a lease."""

import asyncio
from dataclasses import replace
import time

import pytest

from ordin_decision_models import MockDecisionModel, RoutingPolicy, SemanticInspectionRouter
from ordin_decision_models.typesafe import disclosure_action, discover_models

from test_routing import fixture
from test_typesafe import FakeHTTPS, setup as typesafe_setup


def mandatory_policy(**kwargs):
    return RoutingPolicy(
        mode="enforced-escalation",
        deadline_ms=20,
        max_concurrency=1,
        mandatory_action_kinds=("shell",),
        required_question_ids=("material_intent_mismatch",),
        **kwargs,
    )


async def settle(router):
    for _ in range(100):
        if not router.budget_snapshot()["inflight"]:
            return
        await asyncio.sleep(0.01)
    pytest.fail("finished work retained a concurrency lease")


@pytest.mark.parametrize("cancel_caller", [False, True])
def test_uncooperative_provider_returns_promptly_and_retains_lease(cancel_caller):
    async def run():
        canceled, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class Resistant(MockDecisionModel):
            async def evaluate_async(self, *args, **kwargs):
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    canceled.set()
                    await release.wait()
                    return self.evaluate(*args, **kwargs)
                finally:
                    finished.set()

        gate, action, host, _, state = fixture()
        router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=Resistant())
        pending = asyncio.create_task(
            router.evaluate_action_async(action, state=state, host_context=host)
        )
        try:
            if cancel_caller:
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                pending.cancel()
            await asyncio.wait_for(canceled.wait(), 2)
            done, _ = await asyncio.wait((pending,), timeout=0.5)
            assert pending in done, "provider cancellation held the caller past its deadline"
            if cancel_caller:
                with pytest.raises(asyncio.CancelledError):
                    pending.result()
            else:
                result = pending.result()
                assert result.requires_approval and result.model_evidence.error_class == "timeout"
            assert router.budget_snapshot()["inflight"] == 1
            denied = await router.evaluate_action_async(action, state=state, host_context=host)
            assert (
                not denied.model_invoked and "semantic.call_budget_exceeded" in denied.reason_codes
            )
        finally:
            release.set()
            await asyncio.gather(pending, return_exceptions=True)
            await asyncio.wait_for(finished.wait(), 2)
            await settle(router)
        assert router.budget_snapshot()["calls"] == 1

    asyncio.run(run())


@pytest.mark.parametrize("entry", ["direct", "router", "discovery"])
def test_typesafe_late_transport_never_becomes_accepted_and_keeps_nested_lease(tmp_path, entry):
    values = typesafe_setup(tmp_path)
    gate, action, host, state, questions, model, _, config, consent, _ = values

    async def run():
        canceled, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class ResistantHTTPS(FakeHTTPS):
            async def request_json(self, *args, **kwargs):
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    canceled.set()
                    await release.wait()
                    return await super().request_json(*args, **kwargs)
                finally:
                    finished.set()

        transport = ResistantHTTPS()
        model._transport = transport
        router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=model)
        if entry == "direct":
            operation = model.evaluate_async(state, questions, deadline_ms=20)
        elif entry == "discovery":
            operation = discover_models(
                config,
                consent(disclosure_action(config)),
                api_key="synthetic-test-key",
                deadline_ms=20,
                transport=transport,
            )
        else:
            operation = router.evaluate_action_async(action, state=state, host_context=host)
        pending = asyncio.create_task(operation)
        try:
            await asyncio.wait_for(canceled.wait(), 2)
            done, _ = await asyncio.wait((pending,), timeout=0.5)
            assert pending in done, "transport cancellation exceeded the API deadline"
            if entry == "discovery":
                with pytest.raises(asyncio.TimeoutError):
                    pending.result()
            elif entry == "direct":
                assert pending.result().error_class == "timeout"
            else:
                result = pending.result()
                assert result.requires_approval and result.model_evidence.error_class == "timeout"
                assert router.budget_snapshot()["inflight"] == 1
        finally:
            release.set()
            await asyncio.gather(pending, return_exceptions=True)
            await asyncio.wait_for(finished.wait(), 2)
            if entry == "router":
                await settle(router)

    asyncio.run(run())


def test_updated_call_limit_keeps_spent_calls_and_applies_the_new_limit():
    gate, action, host, _, state = fixture()
    model = MockDecisionModel({"material_intent_mismatch": 0.1})
    router = SemanticInspectionRouter(
        gate, policy=mandatory_policy(max_total_calls=2), provider=model
    )
    assert router.evaluate_action(action, state=state, host_context=host).may_execute
    router.policy = replace(router.policy, max_total_calls=1)
    result = router.evaluate_action(action, state=state, host_context=host)
    assert result.requires_approval and not result.model_invoked and model.calls == 1
    assert "semantic.call_budget_exceeded" in result.reason_codes


def test_policy_change_during_inference_keeps_the_original_enforcement_mode():
    gate, action, host, _, state = fixture()

    class Changing(MockDecisionModel):
        def evaluate(self, *args, **kwargs):
            router.policy = replace(router.policy, mode="shadow")
            return super().evaluate(*args, **kwargs)

    router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=Changing())
    result = router.evaluate_action(action, state=state, host_context=host)
    assert result.denied and result.mode == "enforced-escalation"
    assert "semantic.configuration_changed" in result.reason_codes
    assert not router.binding_matches(result, action, state=state, host_context=host)


def test_worker_start_failure_reports_unavailable_without_leaking_a_slot(monkeypatch):
    gate, action, host, _, state = fixture()
    router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=MockDecisionModel())

    def unavailable(self):
        raise RuntimeError("owned unavailable thread fixture")

    monkeypatch.setattr("ordin_decision_models.routing.threading.Thread.start", unavailable)
    result = router.evaluate_action(action, state=state, host_context=host)
    assert result.requires_approval and not result.model_invoked
    assert result.model_evidence.error_class == "unavailable"
    assert router.budget_snapshot()["inflight"] == 0 and router.provider.calls == 0


def test_removed_provider_and_malformed_response_refuse_the_original_request():
    gate, action, host, _, state = fixture()

    class Removing(MockDecisionModel):
        def evaluate(self, *args, **kwargs):
            router.provider = None
            return {}

    router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=Removing())
    result = router.evaluate_action(action, state=state, host_context=host)
    assert result.denied and result.model_evidence.error_class == "malformed"
    assert "semantic.configuration_changed" in result.reason_codes


def test_event_loop_blocking_provider_cannot_accept_an_answer_after_deadline():
    class Blocking(MockDecisionModel):
        async def evaluate_async(self, *args, **kwargs):
            time.sleep(0.05)
            return self.evaluate(*args, **kwargs)

    gate, action, host, _, state = fixture()
    router = SemanticInspectionRouter(gate, policy=mandatory_policy(), provider=Blocking())
    result = asyncio.run(router.evaluate_action_async(action, state=state, host_context=host))
    assert result.requires_approval and result.model_evidence.error_class == "timeout"
