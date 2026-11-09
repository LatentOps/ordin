"""Pure host UID/preparation ordering and original-object custody, not native proof."""

from pathlib import PurePosixPath
from types import SimpleNamespace
from threading import RLock

import pytest

from ordin import ActionEnvelope, AgentGate, ToolCallAdapter
from ordin.assurance.delegation import _verify_operation_authority
from ordin.runtime_contract import derive_runtime_capability_contract
from ordin_swarm.host_authority import HostAuthority, _authority, host_core
from ordin_swarm.host_profiles import HostActor


def setup_host():
    host = object.__new__(HostAuthority)
    host._control_lock, host._closing = RLock(), False
    actor = HostActor("agent", ("document.txt",), ("report.txt",), (), ())
    profile = SimpleNamespace(
        actor=lambda name: actor,
        workspace=PurePosixPath("/workspace"),
        actors=(actor,),
        http_routes=(),
    )
    host.profile = profile
    host.operator, host.scope = object(), object()
    channel, broker_channel = object(), object()
    host.broker_socket = object()
    host.enrollments, host.grants = {"agent": "enrollment"}, {"agent": "original-grant"}

    def require(actual, *, role):
        assert actual is channel and role == "workload"
        return SimpleNamespace(enrollment_id="enrollment")

    host.auth = SimpleNamespace(require=require, authenticate=lambda socket: broker_channel)
    host.maintenance = host.refresh_factory = lambda: None
    host.core = host_core(required_euid=65534)
    host.assurance = SimpleNamespace(baseline_gate=AgentGate(host.core))
    events = []
    host.coordinator = SimpleNamespace(
        admit=lambda *args: SimpleNamespace(reference="lease"),
        bind_grant=lambda *args: events.append("bound-grant"),
    )
    return host, channel, broker_channel, events


def test_original_uid_requirement_makes_fresh_allow_contained_and_keeps_read_semantics():
    host, _, _, _ = setup_host()
    action = ToolCallAdapter("ordin-owned").adapt(
        "read_file", {"path": "/workspace/document.txt"}, action_id="read"
    )
    reviewed = host.core.review_action(action)
    contract = derive_runtime_capability_contract(reviewed)
    actor = host.profile.actor("agent")
    maximum = _authority(host.profile, actor, 65534)
    assert reviewed.decision == "allow" and contract.privilege.required_euid == 65534
    assert _verify_operation_authority(contract, maximum).ok
    assert host_core().review_action(action).decision == reviewed.decision


def test_core_allow_uses_original_coordinator_path_without_human_request_or_result_copy():
    host, channel, broker_channel, events = setup_host()
    action = ToolCallAdapter("ordin-owned").adapt(
        "read_file", {"path": "/workspace/document.txt"}, action_id="original"
    )
    original = SimpleNamespace(forwarded=True, physical_enforcement=True)

    def evaluate(scope, actual, lease, grant, captured, *, idempotency_key):
        assert (
            scope is host.scope
            and actual is channel
            and lease == "lease"
            and grant == "original-grant"
        )
        assert captured is action and idempotency_key == "original-request"
        events.append("ordinary-evaluation")
        return SimpleNamespace(status="execute", reference="original-evaluation")

    def reserve(scope, actual, lease, reference, captured, *, idempotency_key):
        assert scope is host.scope and actual is channel and lease == "lease"
        assert (
            reference == "original-evaluation"
            and captured is action
            and idempotency_key == "original-request"
        )
        events.append("reserved")
        return SimpleNamespace(status="reserved", reference="original-reservation")

    def dispatch(scope, actual, reference):
        assert (
            scope is host.scope and actual is broker_channel and reference == "original-reservation"
        )
        events.append("dispatch")
        return SimpleNamespace(status="host_completed")

    def result(scope, actual, reference):
        assert (
            scope is host.scope and actual is broker_channel and reference == "original-reservation"
        )
        events.append("original-result")
        return original

    host.coordinator.evaluate, host.coordinator.reserve = evaluate, reserve
    host.coordinator.guarded_dispatch, host.coordinator.broker_result = dispatch, result
    host.governance = SimpleNamespace(
        request=lambda *args, **kwargs: pytest.fail(
            "CoreALLOW requested an unnecessary human receipt"
        )
    )
    returned = host.dispatch("agent", channel, action, request_id="original-request")
    assert (
        returned.status == "completed" and returned.result is original and returned.action is action
    )
    assert events == [
        "bound-grant",
        "ordinary-evaluation",
        "reserved",
        "dispatch",
        "original-result",
    ]


def test_warning_queues_exact_original_action_before_ordinary_guard_and_requirements_are_rechecked():
    host, channel, _, events = setup_host()
    action = ToolCallAdapter("ordin-owned").adapt(
        "write_artifact",
        {
            "path": "/workspace/report.txt",
            "content": "exact",
            "expected_version": 0,
            "expected_digest": None,
        },
        action_id="warning",
    )
    assert host.core.review_action(action).decision == "warn"
    approval = object()

    def request(actual, lease, grant, captured, *, idempotency_key):
        assert actual is channel and lease == "lease" and grant == "original-grant"
        assert captured is action and idempotency_key == "original-warning"
        events.append("original-human-request")
        return approval

    host.coordinator.evaluate = lambda *args, **kwargs: pytest.fail(
        "WARN entered ordinary guard before human preparation"
    )
    host.governance = SimpleNamespace(request=request)
    returned = host.dispatch("agent", channel, action, request_id="original-warning")
    assert returned.status == "requires_approval" and returned.forwarded is False
    assert (
        returned.approval is approval and returned.action is action and returned.lease_id == "lease"
    )
    assert events == ["bound-grant", "original-human-request"]

    def unresolved(*args, **kwargs):
        raise ValueError("mandatory original requirement unresolved")

    host.governance.request = unresolved
    rejected = host.dispatch("agent", channel, action, request_id="denied-warning")
    assert rejected.status == "denied" and rejected.forwarded is False and rejected.approval is None


def test_core_block_cannot_enter_human_or_ordinary_route():
    host, channel, _, events = setup_host()
    host.governance = SimpleNamespace(
        request=lambda *args, **kwargs: pytest.fail("block queued human approval")
    )
    host.coordinator.evaluate = lambda *args, **kwargs: pytest.fail(
        "block attempted ordinary preparation"
    )
    returned = host.dispatch(
        "agent", channel, ActionEnvelope.shell("rm -rf /"), request_id="blocked"
    )
    assert returned.status == "denied" and returned.forwarded is False and returned.result is None
    assert events == ["bound-grant"]


def test_current_history_or_policy_rejection_is_not_converted_into_human_approval():
    from ordin.swarm.coordinator_store import CoordinatorRejected

    host, channel, _, events = setup_host()
    action = ToolCallAdapter("ordin-owned").adapt(
        "read_file", {"path": "/workspace/document.txt"}, action_id="original"
    )
    rejection = CoordinatorRejected("independent current history or policy changed")

    def reject(*args, **kwargs):
        events.append("fresh-ordinary-check")
        raise rejection

    host.coordinator.evaluate = reject
    host.governance = SimpleNamespace(
        request=lambda *args, **kwargs: pytest.fail("independent denial became a human bypass")
    )
    with pytest.raises(CoordinatorRejected) as observed:
        host.dispatch("agent", channel, action, request_id="fresh-original")
    assert observed.value is rejection and events == ["bound-grant", "fresh-ordinary-check"]
