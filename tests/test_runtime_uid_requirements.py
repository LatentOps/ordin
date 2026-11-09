"""Host-selected UID requirements tighten containment; they never grant authority."""

from dataclasses import replace
import json

import pytest

from ordin import (
    ActionEnvelope,
    ExecutionContext,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.assurance import DelegationAuthority
from ordin.assurance.delegation import _verify_operation_authority
from ordin.assurance.simulation import _core_packet, _core_from_packet
from ordin.provenance import ProvenanceRecord
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_codec import action_review_from_dict
from ordin.runtime_contract import (
    FilesystemCapability,
    PrivilegeCapability,
    ProcessCapability,
    ToolCapability,
    derive_runtime_capability_contract,
)
from ordin.runtime_requirements import RuntimeRequirementProfile, ToolRuntimeRequirement


def core(requirements=None):
    return Ordin(
        tool_semantics=ToolSemanticsRegistry(
            "uid-tools",
            "1",
            (
                ToolSemanticRule(
                    "read",
                    "tool",
                    "read_file",
                    ("filesystem.read",),
                    runtime="fixture",
                    resources=(ToolResourceBinding("path", "path"),),
                ),
                ToolSemanticRule(
                    "write",
                    "tool",
                    "write_artifact",
                    ("filesystem.write",),
                    runtime="fixture",
                    resources=(ToolResourceBinding("path", "path"),),
                ),
            ),
        ),
        runtime_requirements=requirements,
    )


def action(tool="read_file", **arguments):
    return ToolCallAdapter("fixture").adapt(
        tool, {"path": "/workspace/document.txt", **arguments}, action_id="original"
    )


def maximum():
    return DelegationAuthority(
        RuntimeCapabilityBoundary(
            "owned-worker",
            filesystem=(FilesystemCapability("read", "/workspace/document.txt", "exact"),),
            tools=(ToolCapability("fixture", None, "read_file"),),
            process=ProcessCapability(False, (), False),
            privilege=PrivilegeCapability(False, 65534),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        )
    )


def test_original_unresolved_uid_is_rejected_and_host_exact_uid_is_contained_without_core_rewrite():
    original = core().review_action(action())
    undeclared = derive_runtime_capability_contract(original)
    assert original.decision == "allow" and undeclared.privilege.required_euid is None
    assert (
        _verify_operation_authority(undeclared, maximum()).reason_code
        == "runtime_boundary_uid_unproven"
    )
    declared = RuntimeRequirementProfile("original-worker", required_euid=65534).declare(original)
    actual = derive_runtime_capability_contract(declared)
    assert _verify_operation_authority(actual, maximum()).ok
    assert actual.privilege == PrivilegeCapability(False, 65534)
    assert declared.action == original.action and declared.decision == original.decision
    assert declared.risk == original.risk and declared.effects == original.effects
    wrong = RuntimeRequirementProfile("different-worker", required_euid=1000).declare(original)
    assert (
        _verify_operation_authority(derive_runtime_capability_contract(wrong), maximum()).result
        == "exceeds_boundary"
    )


def test_disabled_uid_preserves_legacy_bytes_digest_and_review_contract():
    legacy = RuntimeRequirementProfile("legacy")
    explicit = RuntimeRequirementProfile("legacy", required_euid=None)
    assert legacy.as_dict() == explicit.as_dict() and legacy.digest == explicit.digest
    assert "required_euid" not in legacy.as_dict()
    original = core().review_action(action())
    assert derive_runtime_capability_contract(
        legacy.declare(original)
    ) == derive_runtime_capability_contract(original)


@pytest.mark.parametrize(
    "value", [True, False, -1, (1 << 32) - 1, 1 << 32, 1 << 128, "65534", 65534.0]
)
def test_invalid_or_reserved_uid_is_not_a_host_requirement(value):
    with pytest.raises(ValueError, match="uid_invalid"):
        RuntimeRequirementProfile("invalid", required_euid=value)


def test_actor_json_and_context_cannot_select_uid_or_activate_a_profile():
    original = action(required_euid=65534, runtime_requirements={"required_euid": 65534})
    original = replace(original, context=ExecutionContext(euid=65534))
    assert (
        derive_runtime_capability_contract(core().review_action(original)).privilege.required_euid
        is None
    )


def test_conflicting_or_malformed_provenance_remains_unresolved_and_escalation_is_preserved():
    first = RuntimeRequirementProfile("first", required_euid=65534).declare(
        core().review_action(action())
    )
    conflict = RuntimeRequirementProfile("second", required_euid=0).declare(first)
    contract = derive_runtime_capability_contract(conflict)
    assert contract.grant_state == "diagnostic" and contract.privilege.required_euid is None
    assert any(
        value.domain == "privilege"
        and value.reason_code == "runtime_contract_conflicting_requirement"
        for value in contract.unknowns
    )
    bad = ProvenanceRecord(
        source="context",
        kind="finding",
        code="runtime.requirement.euid",
        metadata={"required_euid": True, "profile_digest": "a" * 64},
    )
    malformed = replace(first, provenance=first.provenance.append(bad))
    assert derive_runtime_capability_contract(malformed).grant_state == "diagnostic"
    escalated = Ordin().review_action(ActionEnvelope.shell("sudo -u root id"))
    declared = RuntimeRequirementProfile("worker", required_euid=65534).declare(escalated)
    assert derive_runtime_capability_contract(declared).privilege.escalation is True
    opaque = Ordin().review_action(ActionEnvelope.shell("opaque-future-command $INPUT"))
    assert derive_runtime_capability_contract(
        RuntimeRequirementProfile("worker", required_euid=65534).declare(opaque)
    ).unknowns


def test_warning_remains_human_required_and_roundtrips_preserve_exact_uid_and_conditionals():
    requirement = RuntimeRequirementProfile(
        "worker",
        required_euid=65534,
        tool_requirements=(
            ToolRuntimeRequirement(
                "fixture",
                None,
                "run_tests",
                "call",
                "unit",
                filesystem=(FilesystemCapability("read", "/project", "prefix"),),
            ),
        ),
    )
    configured = core(requirement)
    reviewed = configured.review_action(action("write_artifact"))
    contract = derive_runtime_capability_contract(reviewed)
    assert reviewed.decision == "warn" and contract.grant_state == "requires_approval"
    assert contract.privilege.required_euid == 65534
    restored_review = action_review_from_dict(json.loads(json.dumps(reviewed.as_dict())))
    assert derive_runtime_capability_contract(restored_review) == contract
    packet = _core_packet(configured)
    restored_core = _core_from_packet(json.loads(json.dumps(packet)))
    assert restored_core.runtime_requirements.as_dict() == requirement.as_dict()
    assert restored_core.runtime_requirements.digest == requirement.digest
    assert restored_core.review_action(action("write_artifact")).as_dict() == reviewed.as_dict()
    invalid = json.loads(json.dumps(packet))
    invalid["runtime_requirements"]["required_euid"] = True
    with pytest.raises(ValueError):
        _core_from_packet(invalid)
    invalid = json.loads(json.dumps(packet))
    invalid["runtime_requirements"]["tool_requirements"][0]["actor_uid"] = 0
    with pytest.raises(ValueError):
        _core_from_packet(invalid)


@pytest.mark.parametrize("collection", [{}, "", None, True, False])
def test_malformed_empty_conditional_collection_is_rejected_before_normalization(collection):
    packet = _core_packet(core(RuntimeRequirementProfile("worker", required_euid=65534)))
    packet["runtime_requirements"]["tool_requirements"] = collection
    with pytest.raises(ValueError, match="literal collection"):
        _core_from_packet(packet)


@pytest.mark.parametrize("container", [list, tuple])
def test_literal_conditional_collection_and_missing_default_keep_exact_uid_and_records(container):
    original = RuntimeRequirementProfile(
        "worker",
        required_euid=65534,
        tool_requirements=(ToolRuntimeRequirement("fixture", None, "run_tests", "call", "unit"),),
    )
    packet = _core_packet(core(original))
    packet["runtime_requirements"]["tool_requirements"] = container(
        packet["runtime_requirements"]["tool_requirements"]
    )
    restored = _core_from_packet(packet).runtime_requirements
    assert restored.as_dict() == original.as_dict() and restored.digest == original.digest
    empty = RuntimeRequirementProfile("empty", required_euid=65534)
    missing = _core_packet(core(empty))
    assert "tool_requirements" not in missing["runtime_requirements"]
    assert _core_from_packet(missing).runtime_requirements.as_dict() == empty.as_dict()
    missing["runtime_requirements"]["tool_requirements"] = container()
    assert _core_from_packet(missing).runtime_requirements.digest == empty.digest
