"""Fixed-tool host requirements tighten the selected route without changing others."""

from dataclasses import replace

import pytest

from ordin import Ordin, ToolCallAdapter, ToolSemanticRule, ToolSemanticsRegistry
from ordin.runtime_contract import FilesystemCapability, derive_runtime_capability_contract
from ordin.runtime_requirements import RuntimeRequirementProfile, ToolRuntimeRequirement


def profile():
    return RuntimeRequirementProfile(
        "fixed-test-host",
        tool_requirements=(
            ToolRuntimeRequirement(
                "ordin-owned",
                None,
                "run_tests",
                "call",
                "unit",
                filesystem=(FilesystemCapability("read", "/project", "prefix"),),
                client_executables=("/runtime/bin/python",),
                spawn_children=False,
            ),
        ),
    )


def review(name="run_tests", args=None, runtime="ordin-owned", requirements=None):
    semantics = ToolSemanticsRegistry(
        "host-tools",
        "1",
        (
            ToolSemanticRule("test", "tool", "run_tests", ("code.execute",), runtime="ordin-owned"),
            ToolSemanticRule(
                "read", "tool", "read_file", ("filesystem.read",), runtime="ordin-owned"
            ),
        ),
    )
    action = ToolCallAdapter(runtime).adapt(
        name, {"test_id": "unit"} if args is None else args, action_id="host-normalized"
    )
    return Ordin(tool_semantics=semantics, runtime_requirements=requirements).review_action(action)


def test_exact_catalogue_entry_declares_complete_fixed_process_requirements():
    original = review()
    declared = review(requirements=profile())
    contract = derive_runtime_capability_contract(declared)
    assert declared.decision == original.decision == "warn"
    assert declared.risk == original.risk and declared.effects == original.effects
    assert contract.grant_state == "requires_approval" and not contract.unknowns
    assert contract.process.execution is True
    assert contract.process.executables == ("/runtime/bin/python",)
    assert contract.process.spawn_children is False
    assert contract.filesystem == (FilesystemCapability("read", "/project", "prefix"),)


@pytest.mark.parametrize(
    "name,args,runtime",
    [
        ("read_file", {"test_id": "unit"}, "ordin-owned"),
        ("run_tests", {"test_id": "other"}, "ordin-owned"),
        ("run_tests", {"test_id": "unit", "argv": ["--anything"]}, "ordin-owned"),
        ("run_tests", {"test_id": "unit"}, "foreign"),
        ("run_tests", {"test_id": 1}, "ordin-owned"),
    ],
)
def test_other_calls_cannot_acquire_fixed_test_requirements(name, args, runtime):
    original = review(name, args, runtime)
    declared = review(name, args, runtime, profile())
    assert derive_runtime_capability_contract(declared).as_dict() == (
        derive_runtime_capability_contract(original).as_dict()
    )


def test_disabled_field_preserves_original_profile_serialization_and_digest():
    implicit = RuntimeRequirementProfile("old-profile")
    explicit = RuntimeRequirementProfile("old-profile", tool_requirements=())
    assert implicit.as_dict() == explicit.as_dict()
    assert "tool_requirements" not in implicit.as_dict()
    assert implicit.digest == explicit.digest


def test_selector_is_exact_and_duplicate_or_wildcard_configuration_is_refused():
    selected = profile().tool_requirements[0]
    with pytest.raises(ValueError, match="duplicate"):
        RuntimeRequirementProfile("duplicate", tool_requirements=(selected, selected))
    with pytest.raises(ValueError, match="selector"):
        replace(selected, test_id="*")
    different_server = replace(selected, server="another-server")
    assert not different_server.matches(review())
    different_operation = replace(selected, operation="other")
    assert not different_operation.matches(review())


def test_context_requirements_cannot_turn_unknown_tool_semantics_into_permission():
    declared = review(name="unrepresented", requirements=profile())
    contract = derive_runtime_capability_contract(declared)
    assert not contract.process.executables
    assert declared.decision != "allow"
