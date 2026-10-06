from dataclasses import replace

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.enforcement_backend import (
    BackendValidationResult,
    CompilationResult,
    EnforcementBackend,
    EnforcementPlan,
)
from ordin.runtime_contract import derive_runtime_capability_contract


def contract():
    return derive_runtime_capability_contract(
        Ordin().review_action(ActionEnvelope.shell("git status", action_id="one"))
    )


def test_protocol_only_compiles_and_validates_never_executes_or_applies():
    class FixtureBackend:
        name = "fixture"

        def compile(self, candidate):
            return CompilationResult(
                "success",
                self.name,
                "compiled",
                plan=EnforcementPlan(self.name, candidate, {"deny_by_default": True}),
            )

        def validate(self, plan):
            return BackendValidationResult("success", self.name, plan.policy_digest, "validated")

    backend = FixtureBackend()
    assert isinstance(backend, EnforcementBackend)
    result = backend.compile(contract())
    assert result.enforceable
    assert backend.validate(result.plan).ok
    assert not hasattr(EnforcementBackend, "execute_action")
    assert not hasattr(EnforcementBackend, "apply")


def test_plan_is_immutable_action_bound_and_policy_digest_is_deterministic():
    policy = {"network": {"allowed": ["example.com"]}}
    plan = EnforcementPlan("fixture", contract(), policy)
    policy["network"]["allowed"].append("other.example")
    assert plan.policy["network"]["allowed"] == ("example.com",)
    assert (
        plan.policy_digest
        == EnforcementPlan(
            "fixture", contract(), {"network": {"allowed": ["example.com"]}}
        ).policy_digest
    )
    with pytest.raises(TypeError):
        plan.policy["network"]["allowed"] = ()
    assert plan.contract.action_id == "one"


def test_non_success_never_has_an_enforceable_partial_plan():
    plan = EnforcementPlan("fixture", contract(), {})
    with pytest.raises(ValueError):
        CompilationResult(
            "unsupported", "fixture", "missing", unsupported_fields=("network.protocol",), plan=plan
        )
    result = CompilationResult(
        "unsupported", "fixture", "missing", unsupported_fields=("network.protocol",)
    )
    assert not result.enforceable and result.plan is None
    diagnostic = CompilationResult(
        "unsupported",
        "fixture",
        "missing",
        unsupported_fields=("network.protocol",),
        plan=replace(plan, mode="shadow"),
    )
    assert not diagnostic.enforceable and diagnostic.unsupported_fields == ("network.protocol",)
    with pytest.raises(ValueError):
        CompilationResult(
            "success", "fixture", "missing", unsupported_fields=("network.protocol",), plan=plan
        )


def test_block_is_diagnostic_and_ask_never_loses_approval_requirement():
    blocked = replace(contract(), contract_id="", decision="block")
    with pytest.raises(ValueError):
        EnforcementPlan("fixture", blocked, {})
    assert EnforcementPlan("fixture", blocked, {}, mode="shadow").mode == "shadow"
    ask = replace(contract(), contract_id="", decision="ask")
    assert EnforcementPlan("fixture", ask, {}).requires_human_approval


def test_validation_preserves_unknown_fields_and_policy_identity():
    plan = EnforcementPlan("fixture", contract(), {})
    result = BackendValidationResult(
        "unsupported",
        "fixture",
        plan.policy_digest,
        "unsupported_field",
        unsupported_fields=("credential.binding",),
    )
    assert not result.ok
    assert result.as_dict()["unsupported_fields"] == ["credential.binding"]
    with pytest.raises(ValueError):
        BackendValidationResult(
            "success",
            "fixture",
            plan.policy_digest,
            "ok",
            unsupported_fields=("credential.binding",),
        )
