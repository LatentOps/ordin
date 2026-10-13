"""Read-only snapshot triage. Syntax and policy deltas never prove exploitation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from ._json import digest
from .inventory import AuthorizedRepository, inventory_repository
from .inventory_models import InventoryLimits, RepositoryInventory
from .models import JsonRecord, RepositoryScope, SecurityProfile, SourceReference, _unique
from .simulation import SimulationPolicy, policy_authority_delta


@dataclass(frozen=True)
class DiffFile(JsonRecord):
    SCHEMA = "diff_file"
    MANY = {"sources": SourceReference}
    path_digest: str
    change: str
    before_digest: str | None
    after_digest: str | None
    categories: tuple[str, ...]
    sources: tuple[SourceReference, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        if (
            (self.change == "added" and self.before_digest is not None)
            or (self.change == "deleted" and self.after_digest is not None)
            or (self.before_digest is None and self.after_digest is None)
        ):
            raise ValueError("diff file digest/change mismatch")


@dataclass(frozen=True)
class DiffTriageReport(JsonRecord):
    SCHEMA = "assurance_diff_triage"
    NESTED = {"repository_before": RepositoryScope, "repository_after": RepositoryScope}
    MANY = {"changes": DiffFile}
    repository_before: RepositoryScope
    repository_after: RepositoryScope
    baseline_snapshot_digest: str
    candidate_snapshot_digest: str
    baseline_policy_digest: str | None
    candidate_policy_digest: str | None
    policy_authority_delta: str
    profile_changed: bool
    changes: tuple[DiffFile, ...]
    review_required: bool
    completeness: str
    gaps: tuple[str, ...] = ()
    limitations: tuple[str, ...] = (
        "Finite static syntax/path heuristics; aliases, dynamic dispatch and unsupported languages can be missed.",
        "Revision labels require host attestation; no Git command, target import, build, test or scanner is executed.",
        "Changes are review candidates; reachability, exploitation, active enforcement and security are not established.",
    )
    advisory_only: bool = True

    def __post_init__(self):
        super().__post_init__()
        _unique(self.changes, "path_digest")
        if self.repository_before.id != self.repository_after.id:
            raise ValueError("diff requires the same repository identity")
        if self.completeness == "complete" and self.gaps:
            raise ValueError("triage with inspection gaps cannot be complete")
        if self.policy_authority_delta == "widened" and not self.review_required:
            raise ValueError("widened authority always requires review")

    def public_dict(self) -> dict:
        packet = self.as_dict()
        packet["repository_before"] = self.repository_before.digest
        packet["repository_after"] = self.repository_after.digest
        for change in packet["changes"]:
            change["sources"] = [digest("source_reference", source) for source in change["sources"]]
        packet["schema_version"] = "ordin.assurance_diff_triage_summary.v1"
        packet["report_digest"] = self.digest
        return packet


_DEPENDENCIES = {
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "requirements.txt",
    "Pipfile.lock",
    "Cargo.toml",
    "Cargo.lock",
}


def _protected(
    path: str,
    scope: AuthorizedRepository,
    profiles: tuple[SecurityProfile, ...],
    inventories: tuple[RepositoryInventory, ...],
) -> bool:
    target = scope.virtual_root.rstrip("/") + "/" + path
    assets = [asset for profile in profiles for asset in profile.protected_assets]
    assets += [asset for inventory in inventories for asset in inventory.assets]
    return any(
        asset.kind in {"path", "policy"}
        and (
            target == asset.value
            or (asset.match == "prefix" and target.startswith(asset.value.rstrip("/") + "/"))
        )
        for asset in assets
    )


def triage_source_diff(
    before: AuthorizedRepository,
    after: AuthorizedRepository,
    *,
    baseline_policy: SimulationPolicy | None = None,
    candidate_policy: SimulationPolicy | None = None,
    baseline_profile: SecurityProfile | None = None,
    candidate_profile: SecurityProfile | None = None,
    limits: InventoryLimits | None = None,
) -> DiffTriageReport:
    """Compare explicitly authorized snapshots, with optional typed policy content.

    Profiles passed here are inspection data. Selected/compiled profile handles
    in SimulationPolicy retain their normal host trust checks and their changed
    algebra remains unknown where the existing comparator cannot prove it.
    """
    if not isinstance(before, AuthorizedRepository) or not isinstance(after, AuthorizedRepository):
        raise ValueError("diff requires two host-authorized repository snapshots")
    if before.repository.id != after.repository.id or before.virtual_root != after.virtual_root:
        raise ValueError("diff repository identity/action-space mapping mismatch")
    if (baseline_policy is None) != (candidate_policy is None):
        raise ValueError("diff policy inputs require both snapshots")
    if any(
        policy is not None and not isinstance(policy, SimulationPolicy)
        for policy in (baseline_policy, candidate_policy)
    ):
        raise ValueError("diff policies require validated typed content")
    if (baseline_profile is None) != (candidate_profile is None):
        raise ValueError("diff profile inputs require both snapshots")
    for profile, scope in ((baseline_profile, before), (candidate_profile, after)):
        if profile is not None and (
            not isinstance(profile, SecurityProfile) or profile.repository != scope.repository
        ):
            raise ValueError("diff profile scope is stale or mismatched")
    first, second = (
        inventory_repository(before, limits=limits),
        inventory_repository(after, limits=limits),
    )
    old, new = ({file.path: file for file in inventory.files} for inventory in (first, second))
    profiles = tuple(p for p in (baseline_profile, candidate_profile) if p is not None)
    changes = []
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path), new.get(path)
        if a is not None and b is not None and a.content_digest == b.content_digest:
            continue
        categories = set()
        name = PurePosixPath(path).name
        lower = path.lower()
        facts = [fact for fact in second.facts if fact.source.path == path]
        old_facts = Counter(
            (fact.kind, fact.category, fact.enclosing_symbol)
            for fact in first.facts
            if fact.source.path == path
        )
        added_facts = []
        for fact in facts:
            key = (fact.kind, fact.category, fact.enclosing_symbol)
            if old_facts[key]:
                old_facts[key] -= 1
            else:
                added_facts.append(fact)
        for fact in added_facts:
            if fact.kind == "sink" and fact.category.startswith("subprocess."):
                categories.add("new_subprocess_sink")
            if fact.kind == "sink" and fact.category.startswith("network."):
                categories.add("new_network_sink")
            if fact.kind == "entrypoint" and fact.category.startswith("mcp."):
                categories.add("new_tool_surface")
        if _protected(path, after, profiles, (first, second)):
            categories.add("protected_surface")
        if name in _DEPENDENCIES or name.startswith("requirements") and name.endswith(".txt"):
            categories.add("dependency_modified")
        if any(term in lower for term in ("policy", "enforcement", "invariant", "permission")):
            categories.add("enforcement_modified")
        if "mcp" in lower and (
            "schema" in lower or PurePosixPath(path).suffix in {".json", ".yaml", ".yml"}
        ):
            categories.add("mcp_schema_modified")
        if any(
            term in lower for term in ("host", "boundary", "approval", "credential", "delegation")
        ):
            categories.add("host_boundary_modified")
        if not categories:
            categories.add(
                "documentation_only"
                if PurePosixPath(path).suffix == ".md"
                and name.lower() not in {"agents.md", "security.md"}
                else "source_modified"
            )
        references = tuple(f.source for f in added_facts[:16])
        changes.append(
            DiffFile(
                digest("diff_path", path),
                "added" if a is None else "deleted" if b is None else "modified",
                a.content_digest if a else None,
                b.content_digest if b else None,
                tuple(sorted(categories)),
                references,
            )
        )
    authority = (
        policy_authority_delta(baseline_policy, candidate_policy)
        if baseline_policy is not None and candidate_policy is not None
        else "not_supplied"
    )
    profile_changed = bool(
        baseline_profile
        and candidate_profile
        and baseline_profile.digest != candidate_profile.digest
    )
    gaps = sorted({issue.code for inventory in (first, second) for issue in inventory.issues})
    if authority in {"unknown", "unsupported"}:
        gaps.append(
            "Policy containment algebra is unresolved; use reviewed simulation and host evidence."
        )
    review = (
        profile_changed
        or authority not in {"unchanged", "narrowed", "not_supplied"}
        or bool(gaps)
        or any(change.categories != ("documentation_only",) for change in changes)
    )
    return DiffTriageReport(
        before.repository,
        after.repository,
        first.snapshot_digest,
        second.snapshot_digest,
        baseline_policy.digest if baseline_policy else None,
        candidate_policy.digest if candidate_policy else None,
        authority,
        profile_changed,
        tuple(changes),
        review,
        "partial" if gaps else "complete",
        tuple(gaps[:64]),
    )
