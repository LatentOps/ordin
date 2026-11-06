"""Exact actor/action fencing must not widen on identical cross-agent bytes."""

import pytest

from ordin._runtime_json import digest
from tests.assurance.test_delegating_gate import action
from tests.test_swarm_coordinator import configured, prepare
from tests.test_swarm_containment import controller, signal, settled


def test_action_scope_does_not_cancel_another_agents_identical_action_bytes(tmp_path):
    with configured(tmp_path, limit=4) as data:
        value, source = controller(data, maximum=1)
        proposed = action("one")
        _, _, child = prepare(data, "child", request="child", selected_action=proposed)
        _, _, parent = prepare(data, "parent", request="parent", selected_action=proposed)
        receipt = value.quarantine(
            signal(data, source, "action", agent="child"), operator=data["operator"]
        )
        settled(value, receipt, data)
        with data["store"].transaction() as transaction:
            state = transaction.scope(data["scope"].scope_key)
            assert state["reservations"][child.reference]["status"] == "canceled"
            assert state["reservations"][parent.reference]["status"] == "reserved"
        calls = []
        result = data["coordinator"].guarded_dispatch(
            data["scope"],
            data["channels"]["broker-a"],
            parent.reference,
            forward=lambda current: calls.append(current) or "unrelated-parent",
        )
        assert result.status == "host_completed" and len(calls) == 1


def test_explicit_global_action_fence_preserves_legacy_cross_agent_scope(tmp_path):
    with configured(tmp_path, limit=4) as data:
        proposed = action("shared-global")
        _, _, child = prepare(data, "child", request="child", selected_action=proposed)
        _, _, parent = prepare(data, "parent", request="parent", selected_action=proposed)
        data["coordinator"].record_fence(
            data["scope"],
            control=data["control"],
            kind="action",
            subject_digest=digest(proposed.as_dict()),
        )
        with data["store"].transaction() as transaction:
            state = transaction.scope(data["scope"].scope_key)
            assert state["reservations"][child.reference]["status"] == "canceled"
            assert state["reservations"][parent.reference]["status"] == "canceled"


def test_actor_specific_binding_is_never_silently_ignored_on_a_broader_fence(tmp_path):
    with configured(tmp_path) as data:
        with pytest.raises(ValueError, match="only to an action"):
            data["coordinator"].record_fence(
                data["scope"], control=data["control"], kind="swarm", actor_digest="a" * 64
            )
