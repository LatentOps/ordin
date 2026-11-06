"""Actual approval quorum, kernel outcomes and recovery through operator RBAC."""

from contextlib import contextmanager
from copy import copy
import json

import pytest

from ordin.schema import validate_named_schema
from ordin.swarm.audit import SwarmAuditJournal
from ordin.swarm.diagnostics import SwarmAuditSource
from ordin.swarm.incident import (
    IncidentPolicy,
    IncidentScope,
    IncidentSignalSource,
    SwarmContainmentController,
)
from ordin.swarm.operator_api import SwarmOperatorAPI
from tests.test_swarm_approval import configured
from tests.test_swarm_broker import require_kernel
from tests.test_swarm_operator import request as wire_request


@contextmanager
def operator_governance(tmp_path, **options):
    require_kernel()
    with configured(
        tmp_path, operator_roles=("approve", "deny", "observe", "break_glass", "recover"), **options
    ) as data:
        service, coordinator, scope, _, _, _, _, _, _, native = data
        operator = native[11]
        signals = IncidentSignalSource(operator=operator)
        controller = SwarmContainmentController(
            coordinator,
            scope,
            control=service._control,
            operator=operator,
            policy=IncidentPolicy("operator-test", 1),
            signals=signals,
        )
        journal = SwarmAuditJournal(
            tmp_path / "audit.db",
            key=b"K" * 32,
            tenant_id="tenant",
            operator=operator,
            clock=coordinator.clock,
            create=True,
        )
        source = SwarmAuditSource(
            journal,
            coordinator,
            scope,
            control=service._control,
            operator=operator,
            containment=controller,
        )
        api = SwarmOperatorAPI(service.directory, (source,), operator=operator, governance=service)
        try:
            yield data, source, api, controller, signals
        finally:
            source.close(operator=operator)


@pytest.mark.parametrize("decision", ("warn", "ask"))
def test_operator_quorum_retains_original_escalation_and_only_kernel_result_is_observed(
    tmp_path, decision
):
    with operator_governance(tmp_path, quorum=True, decision=decision) as (data, source, api, _, _):
        service, _, _, channel, lease, grant, action, humans, _, native = data
        pending = service.request(channel, lease, grant, action, idempotency_key="original")
        queue = api.handle(humans["alice"], wire_request("status"))
        assert not validate_named_schema("swarm_operator_snapshot", queue)
        reference = queue["approvals"][0]["request_ref"]
        first = api.handle(
            humans["alice"], wire_request("approve", request_ref=reference, idempotency_key="first")
        )
        assert first["status"] == "pending" and not service._receipt_by_request
        final = api.handle(
            humans["bob"], wire_request("approve", request_ref=reference, idempotency_key="second")
        )
        assert final["status"] == "approved"
        assert set(final) == {
            "schema_version",
            "scope_ref",
            "operation",
            "receipt_ref",
            "status",
            "execution_authority",
        }
        receipt = service._receipt_by_request[pending.request_id]
        with pytest.raises(ValueError):
            service.prepare(copy(receipt), channel, lease, action)
        service.prepare(receipt, channel, lease, action)
        original = service._approved(receipt)
        reviewed = native[0].authorization_scope(original.authorization).decision
        assert reviewed.review.decision == decision
        assert reviewed.disposition == "escalate"
        assert source.flush(operator=native[11], timeout=5)
        before = source.journal.export(operator=native[11])
        assert not any(row["evidence"] == "observed" for row in before["events"])
        result = service.dispatch(receipt)
        assert result.status == "host_completed"
        with pytest.raises(ValueError):
            service.dispatch(receipt)
        assert source.flush(operator=native[11], timeout=5)
        bundle = source.journal.export(operator=native[11])
        observed = [row for row in bundle["events"] if row["evidence"] == "observed"]
        assert len(observed) == 1 and observed[0]["kind"] == "broker_result"
        assert observed[0]["facts"]["observed_outcome"] == "completed"
        assert {"task", "session", "tool"} <= set(observed[0]["refs"])
        raw = json.dumps([queue, first, final, bundle])
        assert '"receipt"' not in raw and '"approval"' not in raw
        assert str(action.parameters["arguments"]["path"]) not in raw
        assert "broker-owned-benign-data" not in raw


def test_operator_deny_and_recovery_keep_live_handles_server_owned(tmp_path):
    with operator_governance(tmp_path) as (data, source, api, controller, signals):
        service, coordinator, scope, channel, lease, grant, action, humans, _, native = data
        pending = service.request(channel, lease, grant, action, idempotency_key="deny")
        reference = source.journal.redactor.ref("approval", pending.request_id)
        denied = api.handle(
            humans["alice"], wire_request("deny", request_ref=reference, idempotency_key="no")
        )
        assert denied["status"] == "denied" and not service._receipt_by_request
        signal = signals.operator_signal(
            IncidentScope("agent", "tenant", "swarm", agent_id="child"),
            severity="high",
            operator=native[11],
        )
        incident = controller.pause(signal, operator=native[11])
        assert controller._original(incident).done.wait(10)
        coordinator.start(scope, control=service._control, takeover=True)
        recovery = service.request_recovery(
            humans["alice"],
            controller,
            incident,
            task_id="task",
            reason_code="safety_recovery",
            idempotency_key="recovery",
        )
        queue = api.handle(humans["alice"], wire_request("status"))
        assert not validate_named_schema("swarm_operator_snapshot", queue)
        row = next(row for row in queue["approvals"] if row["mode"] == "recovery")
        assert row["quorum"] == 2 and row["action_ref"] is None
        for principal, status in (("alice", "pending"), ("bob", "approved")):
            result = api.handle(
                humans[principal],
                wire_request("approve", request_ref=row["request_ref"], idempotency_key=principal),
            )
            assert result["status"] == status and not result["execution_authority"]
            assert "approval" not in result and "receipt" not in result
        approval = next(
            handle
            for handle, value in service._recoveries.items()
            if value[0].request_id == recovery.request_id
        )
        service.resume(humans["bob"], approval)
        assert controller._original(incident).resumed
        with pytest.raises(ValueError):
            service.resume(humans["bob"], approval)
