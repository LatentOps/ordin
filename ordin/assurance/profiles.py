"""Protected operator selection and exact, restriction-only policy compilation.

Host code owns selection, active policy identity, principal and filesystem
mapping. These APIs do not install OS protection, sign configuration, execute
actions or accept an agent's JSON as approval.
"""

from __future__ import annotations

import posixpath
import re
import hashlib
from dataclasses import dataclass
from pathlib import Path

from ordin.action_policy import (
    ActionPolicyCondition,
    ActionPolicyRule,
    ActionPolicySet,
    CompiledActionPolicySet,
    PolicyResourceMatcher,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_contract import (
    FilesystemCapability,
    PrivilegeCapability,
    ProcessCapability,
    RuntimeCapabilityContract,
)
from ordin.runtime_observation import RuntimeEvidenceSource

from ._files import read_scoped_file, relative_parts
from ._json import digest, validate
from .models import (
    ApprovedSecurityProfile,
    JsonRecord,
    RepositoryScope,
    SecurityInvariant,
    SecurityProfile,
    SecurityProfileDraft,
    SourceReference,
    _ProfileAuthority,
)

_HEX = re.compile(r"^[a-f0-9]{64}$")
MUTATION_EFFECTS = (
    "filesystem.write",
    "filesystem.delete",
    "filesystem.recursive_delete",
    "filesystem.permission_change",
    "filesystem.recursive_permission_change",
    "filesystem.ownership_change",
    "filesystem.recursive_ownership_change",
)
SUPPORT_FLAGS = frozenset({"source_inventory", "exact_review_selectors", "host_authority_binding"})


@dataclass(frozen=True)
class ProtectedProfileSelection:
    """Operator-owned selection, never deserialized from agent/caller JSON.

    The host must enforce agent_boundary and bind protected_runtime_path to the
    actual config file. RuntimeEvidenceSource identifies its protected policy
    channel; it is not proof that this loader installed that enforcement.
    """

    config_root: Path
    relative_path: str
    protected_runtime_path: str
    repository: RepositoryScope
    expected_profile_digest: str
    expected_file_digest: str
    expected_version: str
    operator_identity: str
    agent_boundary: RuntimeCapabilityBoundary
    runtime_source: RuntimeEvidenceSource

    def __post_init__(self) -> None:
        if not isinstance(self.config_root, Path) or not self.config_root.is_absolute():
            raise ValueError("profile selection requires a protected absolute config root")
        relative_parts(self.relative_path)
        if (
            not isinstance(self.repository, RepositoryScope)
            or not isinstance(self.agent_boundary, RuntimeCapabilityBoundary)
            or not isinstance(self.runtime_source, RuntimeEvidenceSource)
        ):
            raise ValueError(
                "profile selection requires host-owned scope, boundary and policy channel"
            )
        RepositoryScope(self.operator_identity, self.expected_version)
        if any(
            not isinstance(value, str) or not _HEX.fullmatch(value)
            for value in (self.expected_profile_digest, self.expected_file_digest)
        ):
            raise ValueError("profile selection requires a pinned content digest")
        from .models import ProtectedAsset

        ProtectedAsset("selected-config", "policy", self.protected_runtime_path)
        if posixpath.normpath(self.protected_runtime_path) != self.protected_runtime_path:
            raise ValueError("protected config runtime path must be canonical")
        _check_profile_protection(self)

    @property
    def digest(self) -> str:
        return digest(
            "operator_profile_selection",
            {
                "config_root_digest": digest("protected_config_root", str(self.config_root)),
                "relative_path_digest": digest("protected_config_path", self.relative_path),
                "runtime_path_digest": digest(
                    "protected_runtime_path", self.protected_runtime_path
                ),
                "repository": self.repository.as_dict(),
                "profile_digest": self.expected_profile_digest,
                "file_digest": self.expected_file_digest,
                "version": self.expected_version,
                "operator_identity": self.operator_identity,
                "boundary_digest": self.agent_boundary.digest,
                "runtime_source_key": self.runtime_source.key,
            },
        )


def _check_profile_protection(selection: ProtectedProfileSelection) -> None:
    boundary = selection.agent_boundary
    if not boundary.runtime_filesystem_guarantees or boundary.privilege.escalation is not False:
        raise ValueError(
            "profile protection requires host-enforced filesystem guarantees and bounded privilege"
        )
    if boundary.privilege.required_euid == 0:
        raise ValueError("root-agent profile protection is unsupported")
    if any(
        cap.access not in {"read", "metadata", "write", "delete", "execute"}
        or cap.path is None
        or cap.scope not in {"exact", "prefix"}
        for cap in boundary.filesystem
    ):
        raise ValueError("unknown filesystem authority cannot establish config protection")
    paths = []
    path = selection.protected_runtime_path
    while path not in paths:
        paths.append(path)
        if path == "/":
            break
        path = posixpath.dirname(path)
    if len(paths) > 128:
        raise ValueError("protected config ancestor limit exceeded")
    for path in paths:
        for access in ("write", "delete"):
            requirement = RuntimeCapabilityContract(
                action_id=None,
                action_digest=digest("protected_path_probe", [path, access]),
                decision="allow",
                risk="low",
                filesystem=(FilesystemCapability(access, path),),
                process=ProcessCapability(False, (), False),
                privilege=PrivilegeCapability(False, boundary.privilege.required_euid),
                source={
                    "kind": "file",
                    "operation": access,
                    "adapter": "assurance.profile_protection_probe",
                    "effects": ["filesystem." + access],
                    "provenance_digest": None,
                },
            )
            result = verify_runtime_capability(requirement, boundary)
            if result.result == "within_boundary":
                raise ValueError("protected profile or ancestor is writable by the protected agent")
            if result.result != "exceeds_boundary" or not all(result.coverage.values()):
                raise ValueError("profile filesystem protection is unsupported or inconclusive")


def inspect_profile(path: Path) -> SecurityProfile:
    """Validate local content, without approval, discovery or activation."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("profile inspection requires an explicit absolute path")
    return SecurityProfile.from_json(read_scoped_file(path.parent, path.name))


def load_approved_profile(
    selection: ProtectedProfileSelection,
    *,
    current_repository: RepositoryScope,
    active_runtime_policy_digest: str,
) -> ApprovedSecurityProfile:
    if not isinstance(selection, ProtectedProfileSelection) or not isinstance(
        current_repository, RepositoryScope
    ):
        raise ValueError("profile activation requires a protected host selection and scope")
    if current_repository != selection.repository:
        raise ValueError("profile repository identity or revision is stale")
    if active_runtime_policy_digest != selection.runtime_source.policy_digest:
        raise ValueError("profile protection policy changed")
    _check_profile_protection(selection)
    content = read_scoped_file(selection.config_root, selection.relative_path, private=True)
    if hashlib.sha256(content).hexdigest() != selection.expected_file_digest:
        raise ValueError("selected profile bytes changed")
    profile = SecurityProfile.from_json(content)
    if profile.repository != current_repository or profile.version != selection.expected_version:
        raise ValueError("profile content scope or version mismatch")
    if profile.digest != selection.expected_profile_digest:
        raise ValueError("selected profile bytes changed")
    if not set(profile.support_flags) <= SUPPORT_FLAGS:
        raise ValueError("selected profile support flags are unsupported")
    if any(
        asset.kind in {"path", "policy"} and posixpath.normpath(asset.value) != asset.value
        for asset in profile.protected_assets
    ):
        raise ValueError("selected profile asset path syntax is ambiguous")
    authority = _ProfileAuthority(
        profile.digest,
        selection.digest,
        selection.operator_identity,
        selection.runtime_source.policy_digest,
    )
    return ApprovedSecurityProfile(
        profile, selection.operator_identity, selection.digest, authority
    )


def propose_profile(
    draft: SecurityProfileDraft, *, profile_id: str, version: str
) -> SecurityProfile:
    """Create reviewable content only. It still requires separate operator selection."""
    if not isinstance(draft, SecurityProfileDraft):
        raise ValueError("profile proposal requires a non-authoritative draft")
    return SecurityProfile(
        profile_id,
        version,
        draft.repository,
        draft.protected_assets,
        draft.trust_boundaries,
        draft.invariant_suggestions,
    )


@dataclass(frozen=True)
class InvariantCompilation(JsonRecord):
    SCHEMA = "invariant_compilation"
    invariant_id: str
    status: str
    reason_code: str
    rule_id: str | None = None


@dataclass(frozen=True)
class CompiledSecurityProfile:
    approved_profile: ApprovedSecurityProfile
    action_policy: CompiledActionPolicySet
    rules: tuple[InvariantCompilation, ...]
    source_references: tuple[SourceReference, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.approved_profile, ApprovedSecurityProfile) or not isinstance(
            self.action_policy, CompiledActionPolicySet
        ):
            raise ValueError("profile compilation requires approved content and typed policy")
        if any(rule.decision not in {"ask", "block"} for rule in self.action_policy.active_rules):
            raise ValueError("profile compilation cannot grant allow or warn")
        if not isinstance(self.rules, (tuple, list)) or not isinstance(
            self.source_references, (tuple, list)
        ):
            raise ValueError("profile compilation requires bounded immutable records")
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "source_references", tuple(self.source_references))
        expected_policy, expected_rules, expected_sources = _compile_profile_parts(
            self.approved_profile
        )
        if (
            self.action_policy.policy != expected_policy.policy
            or (self.action_policy.active_rules != expected_policy.active_rules)
            or self.rules != expected_rules
            or self.source_references != expected_sources
        ):
            raise ValueError("profile compilation does not match approved content")
        validate("assurance_profile_compilation", self.as_dict())

    @property
    def digest(self) -> str:
        return digest("profile_compilation", self.as_dict())

    def as_dict(self) -> dict:
        profile = self.approved_profile.profile
        return {
            "schema_version": "ordin.assurance_profile_compilation.v1",
            "repository": profile.repository.as_dict(),
            "profile_id": profile.profile_id,
            "version": profile.version,
            "profile_digest": profile.digest,
            "selection_digest": self.approved_profile.selection_digest,
            "compiled_policy_digest": self.action_policy.digest,
            "rules": [rule.as_dict() for rule in self.rules],
            "source_references": [source.as_dict() for source in self.source_references],
            "limitations": [
                "Restriction data is not an execution grant or OS enforcement proof.",
                "Wrapper-required and unsupported invariants must not be silently skipped.",
                "Path selectors compare lexical review resources; the host enforces actual objects.",
            ],
        }


def compile_approved_profile(approved: ApprovedSecurityProfile) -> CompiledSecurityProfile:
    policy, rules, sources = _compile_profile_parts(approved)
    return CompiledSecurityProfile(approved, policy, rules, sources)


def _compile_profile_parts(
    approved: ApprovedSecurityProfile,
) -> tuple[CompiledActionPolicySet, tuple[InvariantCompilation, ...], tuple[SourceReference, ...]]:
    if not isinstance(approved, ApprovedSecurityProfile):
        raise ValueError("draft or unapproved profile cannot compile active restrictions")
    profile = approved.profile
    assets = {asset.id: asset for asset in profile.protected_assets}
    rules = []
    support = []
    for invariant in profile.invariants:
        selectors = invariant.selectors
        if selectors.principal is not None:
            support.append(
                InvariantCompilation(
                    invariant.invariant_id, "wrapper_required", "host_principal_required"
                )
            )
            continue
        if invariant.kind not in {"forbid_effect", "protected_policy_mutation"}:
            support.append(
                InvariantCompilation(
                    invariant.invariant_id, "wrapper_required", "typed_host_evidence_required"
                )
            )
            continue
        if invariant.authority_ref is not None:
            support.append(
                InvariantCompilation(
                    invariant.invariant_id, "wrapper_required", "authority_binding_required"
                )
            )
            continue
        if invariant.kind == "forbid_effect" and not selectors.effects:
            support.append(
                InvariantCompilation(
                    invariant.invariant_id, "unsupported", "forbidden_effect_missing"
                )
            )
            continue
        effects = selectors.effects
        if invariant.kind == "protected_policy_mutation":
            effects = tuple(
                effect
                for effect in MUTATION_EFFECTS
                if not selectors.effects or effect in selectors.effects
            )
            if not effects or selectors.resource_ref is None:
                support.append(
                    InvariantCompilation(
                        invariant.invariant_id, "unsupported", "protected_mutation_scope_missing"
                    )
                )
                continue
        resource_matchers: tuple[PolicyResourceMatcher, ...] = ()
        if selectors.resource_ref is not None:
            asset = assets[selectors.resource_ref]
            if asset.kind not in {"path", "policy"}:
                support.append(
                    InvariantCompilation(
                        invariant.invariant_id,
                        "wrapper_required",
                        "typed_resource_identity_required",
                    )
                )
                continue
            # Preserve the legacy literal-prefix API. A new profile directory
            # scope is exact-or-slash-prefix, so /repo cannot match /repo2.
            resource_matchers = (PolicyResourceMatcher("path", asset.value, "exact"),)
            if asset.match == "prefix":
                resource_matchers += (
                    PolicyResourceMatcher("path", asset.value.rstrip("/") + "/", "prefix"),
                )
        rules.append(
            ActionPolicyRule(
                invariant.invariant_id,
                "block" if invariant.on_violation == "block" else "ask",
                ActionPolicyCondition(
                    kinds=selectors.kinds, effects_any=effects, resources_any=resource_matchers
                ),
                reason="operator-selected invariant " + invariant.invariant_id,
            )
        )
        support.append(
            InvariantCompilation(
                invariant.invariant_id, "compiled", "exact_review_selector", invariant.invariant_id
            )
        )
    policy = ActionPolicySet(
        "assurance-" + profile.digest[:24], profile.version, tuple(rules)
    ).compile()
    sources = tuple(
        dict.fromkeys(
            link.source
            for invariant in profile.invariants
            for link in invariant.provenance
            if link.source is not None
        )
    )
    return policy, tuple(support), sources
