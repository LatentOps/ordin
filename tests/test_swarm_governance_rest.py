"""An exact REST envelope preserves its separate mandatory commitment requirement."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from ordin import AgentGate
from ordin._runtime_json import digest
from ordin.assurance.rest import EXACT_REQUIREMENT, RestRequestContract
from ordin.runtime_boundary import verify_runtime_capability
from ordin.swarm.approval_service import SwarmApprovalService
from tests.assurance.test_rest import GET, configured


def preview(gate, context, action=GET, *, contract_digest):
    return SimpleNamespace(
        review=gate.evaluate_action(action, host_context=context).review,
        _context=context,
        action_digest=digest(action.as_dict()),
        contract_digest=contract_digest,
    )


def test_complete_rest_preview_keeps_marker_and_does_not_become_generic_capability(tmp_path):
    approved, _, gate, expected, maximum, context = configured(tmp_path)
    original = preview(gate, context, contract_digest=expected.digest)
    complete = SwarmApprovalService._ordinary_contract(original, approved.digest)
    assert type(complete) is RestRequestContract
    assert complete.digest == expected.digest
    assert [(value.domain, value.reason_code) for value in complete.capability.unknowns] == [
        ("network", EXACT_REQUIREMENT)
    ]
    assert complete.capability.grant_state == "diagnostic"
    assert not verify_runtime_capability(complete.capability, maximum.capability).ok


@pytest.mark.parametrize(
    "parameters",
    [
        {"method": "DELETE"},
        {"url": "https://fixture.invalid/admin"},
        {"headers": {"X-Route": "changed"}},
        {"body": "changed"},
    ],
)
def test_changed_complete_request_cannot_borrow_original_delegated_digest(tmp_path, parameters):
    approved, _, gate, contract, _, context = configured(tmp_path)
    changed = replace(GET, parameters={**GET.parameters, **parameters})
    with pytest.raises(ValueError):
        SwarmApprovalService._ordinary_contract(
            preview(gate, context, changed, contract_digest=contract.digest), approved.digest
        )


def test_default_unselected_rest_semantics_are_not_promoted_by_governance(tmp_path):
    approved, _, _, contract, _, context = configured(tmp_path)
    with pytest.raises(ValueError):
        SwarmApprovalService._ordinary_contract(
            SimpleNamespace(
                review=AgentGate().evaluate_action(GET).review,
                _context=context,
                action_digest=digest(GET.as_dict()),
                contract_digest=contract.digest,
            ),
            approved.digest,
        )
