"""Real managed CAS writes require current protected human fulfillment."""

from dataclasses import replace
import hashlib

import pytest

from tests.test_swarm_approval import configured
from tests.test_swarm_broker import require_kernel


def write_action(native, **kwargs):
    from tests.swarm_owned_tools_samples import OwnedConfiguration

    return OwnedConfiguration(*native).write_action(**kwargs)


def test_actual_managed_write_keeps_warning_and_requires_one_original_human_job(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow", owned_tools=True) as data:
        service, coordinator, scope, channel, lease, grant, _, humans, _, native = data
        target, backend, operator = native[13], native[3], native[11]
        content = "human-approved atomic report\n"
        action = write_action(native, content=content)
        before = target.read_bytes()
        with pytest.raises(ValueError):
            coordinator.evaluate(scope, channel, lease, grant, action, idempotency_key="no-human")
        assert target.read_bytes() == before
        request = service.request(channel, lease, grant, action, idempotency_key="managed")
        assert request.risk == "medium" and "filesystem.write" in request.effects
        assert request.disposition == "escalate"
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="approve")
        accounting = service.fulfill(humans["alice"], request.request_id)
        assert accounting.status == "host_completed", accounting.as_dict()
        actual = service.fulfillment_result(humans["alice"], request.request_id)
        assert actual.status == "completed" and actual.physical_enforcement
        assert actual.executor_outcome.observation.operation == "filesystem.write"
        assert target.read_bytes() == content.encode()
        after = backend.snapshot(str(target), operator=operator)
        assert after["version"] == action.parameters["arguments"]["expected_version"] + 1
        assert after["content_digest"] == hashlib.sha256(content.encode()).hexdigest()
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert target.read_bytes() == content.encode()


def test_managed_write_approval_cannot_substitute_content_or_cas_inputs(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow", owned_tools=True) as data:
        service, _, _, channel, lease, grant, _, humans, _, native = data
        action = write_action(native)
        before = native[13].read_bytes()
        request = service.request(channel, lease, grant, action, idempotency_key="exact")
        resolution = service.resolve(
            humans["alice"], request.request_id, "approve", idempotency_key="yes"
        )
        arguments = action.parameters["arguments"]
        for mutation in (
            {"content": "different"},
            {"expected_version": arguments["expected_version"] + 1},
            {"expected_digest": "a" * 64},
        ):
            changed = replace(
                action,
                parameters={**action.parameters, "arguments": {**arguments, **mutation}},
            )
            with pytest.raises(ValueError):
                service.prepare(resolution["receipt"], channel, lease, changed)
            assert native[13].read_bytes() == before
        assert service.fulfill(humans["alice"], request.request_id).status == "host_completed"


def test_approved_managed_write_rechecks_external_change_before_effect(tmp_path):
    require_kernel()
    with configured(tmp_path, decision="allow", owned_tools=True) as data:
        service, _, _, channel, lease, grant, _, humans, _, native = data
        action = write_action(native)
        request = service.request(channel, lease, grant, action, idempotency_key="cas")
        service.resolve(humans["alice"], request.request_id, "approve", idempotency_key="yes")
        # Only this new test-owned workspace is changed by the simulated external writer.
        external = b"external operator edit\n"
        native[13].write_bytes(external)
        with pytest.raises(ValueError):
            service.fulfill(humans["alice"], request.request_id)
        assert native[13].read_bytes() == external
        assert not native[0]._results
