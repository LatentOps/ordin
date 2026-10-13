import hashlib
import json
import os
from dataclasses import replace

import pytest

from ordin import (
    ActionEnvelope,
    AgentGate,
    Ordin,
    ToolCallAdapter,
    ToolResourceBinding,
    ToolSemanticRule,
    ToolSemanticsRegistry,
)
from ordin.assurance._files import ScopedFileError
from ordin.assurance.models import (
    InvariantSelectors,
    ProtectedAsset,
    RepositoryScope,
    SecurityInvariant,
    SecurityProfile,
    SecurityProfileDraft,
)
from ordin.assurance.profiles import (
    ProtectedProfileSelection,
    compile_approved_profile,
    inspect_profile,
    load_approved_profile,
    propose_profile,
)
from ordin.policy import ENFORCEMENT_ORDER
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource

REPO = RepositoryScope("fixture/repo", "snapshot-1")
POLICY_HASH = "a" * 64


def config_profile(*rules, flags=()):
    return SecurityProfile(
        "fixture",
        "1",
        REPO,
        (ProtectedAsset("prod", "path", "/fixture/prod", "prefix"),),
        invariants=rules,
        support_flags=flags,
    )


def selected(tmp_path, profile, **changes):
    directory = tmp_path / "protected"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / "profile.json"
    path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
    path.chmod(0o600)
    values = dict(
        config_root=directory.resolve(),
        relative_path="profile.json",
        protected_runtime_path="/trusted/profiles/profile.json",
        repository=REPO,
        expected_profile_digest=profile.digest,
        expected_file_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
        expected_version="1",
        operator_identity="fixture-operator",
        agent_boundary=RuntimeCapabilityBoundary(
            "fixture-agent",
            filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        ),
        runtime_source=RuntimeEvidenceSource("fixture", "b" * 64, "fixture-sandbox", POLICY_HASH),
    )
    values.update(changes)
    return ProtectedProfileSelection(**values)


def approve(selection):
    return load_approved_profile(
        selection, current_repository=REPO, active_runtime_policy_digest=POLICY_HASH
    )


def test_validation_and_draft_conversion_are_not_approval(tmp_path):
    draft = SecurityProfileDraft("draft", REPO, "static")
    profile = propose_profile(draft, profile_id="draft-proposal", version="1")
    selection = selected(tmp_path, profile)
    inspected = inspect_profile(selection.config_root / selection.relative_path)
    assert inspected == profile
    with pytest.raises(ValueError, match="unapproved"):
        compile_approved_profile(inspected)
    with pytest.raises(ValueError, match="unapproved"):
        compile_approved_profile(draft)
    with pytest.raises(ValueError, match="protected host selection"):
        load_approved_profile(
            profile.as_dict(), current_repository=REPO, active_runtime_policy_digest=POLICY_HASH
        )


def test_explicit_operator_selection_binds_profile_scope_content_and_active_policy(tmp_path):
    profile = config_profile(
        SecurityInvariant(
            "deny-production-write",
            "forbid_effect",
            InvariantSelectors(effects=("filesystem.write",), resource_ref="prod"),
            on_violation="block",
        )
    )
    selection = selected(tmp_path, profile)
    approved = approve(selection)
    assert approved.profile == profile
    assert approved.digest == profile.digest
    assert approved.selection_digest == selection.digest
    assert approved.runtime_policy_digest == POLICY_HASH
    with pytest.raises(ValueError, match="stale"):
        load_approved_profile(
            selection,
            current_repository=replace(REPO, revision="other"),
            active_runtime_policy_digest=POLICY_HASH,
        )
    with pytest.raises(ValueError, match="policy changed"):
        load_approved_profile(
            selection, current_repository=REPO, active_runtime_policy_digest="c" * 64
        )
    with pytest.raises(ValueError, match="mismatch"):
        approve(replace(selection, expected_version="2"))


def test_whitespace_and_meaningful_profile_changes_both_invalidate_the_selected_bytes(tmp_path):
    selection = selected(tmp_path, config_profile())
    path = selection.config_root / selection.relative_path
    original = path.read_bytes()
    path.write_bytes(original + b"\n")
    with pytest.raises(ValueError, match="bytes changed"):
        approve(selection)
    path.write_text(json.dumps(replace(config_profile(), version="2").as_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="bytes changed"):
        approve(selection)


@pytest.mark.parametrize(
    "capability",
    [
        FilesystemCapability("write", "/trusted", "prefix"),
        FilesystemCapability("delete", "/trusted/profiles", "exact"),
        FilesystemCapability("write", "/trusted/profiles/profile.json", "exact"),
        FilesystemCapability("write", "/", "exact"),
    ],
)
def test_agent_authority_to_mutate_profile_or_ancestor_cannot_activate_it(tmp_path, capability):
    boundary = RuntimeCapabilityBoundary(
        "unsafe",
        filesystem=(capability,),
        filesystem_semantics="lexical_prefix",
        runtime_filesystem_guarantees=True,
    )
    with pytest.raises(ValueError, match="writable"):
        selected(tmp_path, config_profile(), agent_boundary=boundary)


def test_unknown_or_unenforced_filesystem_protection_is_refused(tmp_path):
    with pytest.raises(ValueError, match="host-enforced"):
        selected(tmp_path, config_profile(), agent_boundary=RuntimeCapabilityBoundary("unproven"))
    boundary = RuntimeCapabilityBoundary(
        "unknown",
        filesystem=(FilesystemCapability("unknown", None, "unknown"),),
        runtime_filesystem_guarantees=True,
    )
    with pytest.raises(ValueError, match="unknown filesystem"):
        selected(tmp_path, config_profile(), agent_boundary=boundary)
    with pytest.raises(ValueError):
        selected(tmp_path, config_profile(), relative_path="../outside.json")


def test_profile_scope_and_digest_cannot_be_self_approved_by_json(tmp_path):
    selection = selected(tmp_path, config_profile())
    path = selection.config_root / selection.relative_path
    payload = config_profile().as_dict()
    payload["approved"] = True
    content = json.dumps(payload).encode()
    path.write_bytes(content)
    with pytest.raises(ValueError):
        approve(replace(selection, expected_file_digest=hashlib.sha256(content).hexdigest()))
    selection = selected(tmp_path, config_profile())
    with pytest.raises(ValueError, match="bytes changed"):
        approve(replace(selection, expected_file_digest="f" * 64))
    with pytest.raises(ValueError, match="bytes changed"):
        approve(replace(selection, expected_profile_digest="f" * 64))
    unsupported = selected(tmp_path, config_profile(flags=("enable_unreviewed_extensions",)))
    with pytest.raises(ValueError, match="support flags"):
        approve(unsupported)


def test_profile_hardlinks_are_refused_without_leaking_open_handles(tmp_path):
    selection = selected(tmp_path, config_profile())
    path = selection.config_root / selection.relative_path
    second = tmp_path / "alias.json"
    os.link(path, second)
    with pytest.raises(ScopedFileError, match="hardlink"):
        approve(selection)
    # A failed open must release Windows handles; deletion/rename remains possible.
    second.unlink()
    moved = path.with_name("moved.json")
    path.rename(moved)
    moved.rename(path)
    assert approve(selection).profile.profile_id == "fixture"


def test_precise_restrictions_and_baseline_no_downgrade_on_varied_actions(tmp_path):
    invariant = SecurityInvariant(
        "production-mutation",
        "protected_policy_mutation",
        InvariantSelectors(resource_ref="prod"),
        on_violation="block",
    )
    plan = compile_approved_profile(approve(selected(tmp_path, config_profile(invariant))))
    assert plan.rules[0].status == "compiled"
    assert plan.action_policy.active_rules[0].decision == "block"
    adapter = ToolCallAdapter("fixture-agent")
    semantics = ToolSemanticsRegistry(
        "fixture-files",
        "1",
        (
            ToolSemanticRule(
                "write",
                "tool",
                "write_file",
                ("filesystem.write",),
                runtime="fixture-agent",
                resources=(ToolResourceBinding("path", "path"),),
            ),
            ToolSemanticRule(
                "read",
                "tool",
                "read_file",
                ("filesystem.read",),
                runtime="fixture-agent",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    cases = [
        ActionEnvelope.shell("git status --short"),
        ActionEnvelope.shell("rm -rf /"),
        adapter.adapt("write_file", {"path": "/fixture/prod/config.json"}),
        adapter.adapt("write_file", {"path": "/fixture/prod2/config.json"}),
        adapter.adapt("read_file", {"path": "/fixture/prod/config.json"}),
        adapter.adapt("write_file", {"path": "/fixture/docs/README.md"}),
    ]
    baseline = AgentGate(Ordin(tool_semantics=semantics))
    protected = AgentGate(Ordin(action_policy=plan.action_policy, tool_semantics=semantics))
    for action in cases:
        original = baseline.evaluate_action(action)
        candidate = protected.evaluate_action(action)
        assert (
            ENFORCEMENT_ORDER[candidate.review.decision]
            >= ENFORCEMENT_ORDER[original.review.decision]
        )
        arguments = action.parameters.get("arguments", {})
        if (
            arguments.get("path") == "/fixture/prod/config.json"
            and action.parameters.get("tool") == "write_file"
        ):
            assert candidate.disposition == "deny"
            assert candidate.review.policy_matches[0]["rule_id"] == invariant.invariant_id
        elif arguments.get("path"):
            assert candidate.disposition == original.disposition
            assert not candidate.review.policy_matches
    unknown = ActionEnvelope("file", "write", {"path": "/fixture/prod/config.json"})
    assert (
        protected.evaluate_action(unknown).disposition
        == baseline.evaluate_action(unknown).disposition
        == "escalate"
    )
    assert protected.evaluate_action(unknown).review.effects == []


def test_missing_host_evidence_is_not_projected_to_an_overbroad_catch_all_rule(tmp_path):
    rules = (
        SecurityInvariant("approval", "require_approval", InvariantSelectors(resource_ref="prod")),
        SecurityInvariant("flow", "source_flow_guard", InvariantSelectors()),
        SecurityInvariant("child", "delegated_authority_subset", InvariantSelectors()),
        SecurityInvariant(
            "principal",
            "forbid_effect",
            InvariantSelectors(effects=("filesystem.write",), principal="child"),
        ),
        SecurityInvariant("missing-effect", "forbid_effect", InvariantSelectors()),
    )
    plan = compile_approved_profile(approve(selected(tmp_path, config_profile(*rules))))
    assert plan.action_policy.active_rules == ()
    assert all(row.status in {"wrapper_required", "unsupported"} for row in plan.rules)
    assert plan.rules[-1].reason_code == "forbidden_effect_missing"
    assert plan.as_dict()["limitations"]


def test_tampered_compilation_cannot_remove_an_approved_constraint(tmp_path):
    from ordin.action_policy import CompiledActionPolicySet

    profile = config_profile(
        SecurityInvariant(
            "deny-write",
            "forbid_effect",
            InvariantSelectors(effects=("filesystem.write",)),
            on_violation="block",
        )
    )
    plan = compile_approved_profile(approve(selected(tmp_path, profile)))
    changed = CompiledActionPolicySet(plan.action_policy.policy, ())
    with pytest.raises(ValueError, match="does not match"):
        replace(plan, action_policy=changed)
    with pytest.raises(ValueError, match="does not match"):
        replace(plan, rules=())


def test_noncanonical_asset_paths_and_unproven_prefix_protection_refuse_activation(tmp_path):
    malformed = replace(
        config_profile(), protected_assets=(ProtectedAsset("prod", "path", "/fixture//prod"),)
    )
    with pytest.raises(ValueError, match="ambiguous"):
        approve(selected(tmp_path, malformed))
    boundary = RuntimeCapabilityBoundary(
        "unproven-prefix",
        filesystem=(FilesystemCapability("write", "/trusted", "prefix"),),
        runtime_filesystem_guarantees=True,
    )
    with pytest.raises(ValueError, match="unsupported or inconclusive"):
        selected(tmp_path, config_profile(), agent_boundary=boundary)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode checks require POSIX CI")
def test_group_readable_selected_profile_is_not_a_private_configuration(tmp_path):
    selection = selected(tmp_path, config_profile())
    path = selection.config_root / selection.relative_path
    path.chmod(0o640)
    with pytest.raises(ScopedFileError, match="permissions_invalid"):
        approve(selection)
