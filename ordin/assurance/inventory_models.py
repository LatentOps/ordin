"""Source references and hypotheses for scoped, offline repository inspection."""

from __future__ import annotations

from dataclasses import dataclass

from ._json import digest
from .models import (
    JsonRecord,
    ProtectedAsset,
    RepositoryScope,
    SecurityProfileDraft,
    SourceReference,
    _unique,
)


@dataclass(frozen=True)
class InventoryLimits(JsonRecord):
    SCHEMA = "inventory_limits"
    max_files: int = 256
    max_total_bytes: int = 16_777_216
    max_depth: int = 8


@dataclass(frozen=True)
class InventoryFile(JsonRecord):
    SCHEMA = "inventory_file"
    path: str
    content_digest: str
    bytes: int
    lines: int
    language: str


@dataclass(frozen=True)
class InventoryFact(JsonRecord):
    SCHEMA = "inventory_fact"
    NESTED = {"source": SourceReference}
    fact_id: str
    kind: str
    category: str
    source: SourceReference
    enclosing_symbol: str | None = None


@dataclass(frozen=True)
class InventoryIssue(JsonRecord):
    SCHEMA = "inventory_issue"
    code: str
    path_digest: str | None = None


@dataclass(frozen=True)
class RepositoryInventory(JsonRecord):
    SCHEMA = "assurance_repository_inventory"
    NESTED = {"repository": RepositoryScope, "limits": InventoryLimits}
    MANY = {
        "files": InventoryFile,
        "facts": InventoryFact,
        "assets": ProtectedAsset,
        "issues": InventoryIssue,
    }
    repository: RepositoryScope
    snapshot_digest: str
    root_identity_digest: str
    limits: InventoryLimits
    files: tuple[InventoryFile, ...] = ()
    facts: tuple[InventoryFact, ...] = ()
    assets: tuple[ProtectedAsset, ...] = ()
    issues: tuple[InventoryIssue, ...] = ()
    completeness: str = "unknown"
    generator: str = "ordin.static_inventory.v1"

    def snapshot_material(self) -> dict:
        return {
            "repository": self.repository.as_dict(),
            "files": [f.as_dict() for f in self.files],
            "issues": [issue.as_dict() for issue in self.issues],
            "assets": [asset.as_dict() for asset in self.assets],
            "limits": self.limits.as_dict(),
        }

    def __post_init__(self) -> None:
        super().__post_init__()
        _unique(self.files, "path")
        _unique(self.facts, "fact_id")
        _unique(self.assets, "id")
        files = {file.path: file for file in self.files}
        for fact in self.facts:
            file = files.get(fact.source.path)
            if (
                file is None
                or fact.source.content_digest != file.content_digest
                or (
                    fact.source.revision != self.repository.revision
                    or fact.source.line > file.lines
                )
            ):
                raise ValueError("inventory source reference mismatch")
        if self.snapshot_digest != digest("repository_snapshot", self.snapshot_material()):
            raise ValueError("inventory snapshot digest mismatch")
        if self.completeness == "complete" and self.issues:
            raise ValueError("inventory with inspection gaps cannot be complete")


@dataclass(frozen=True)
class RouteHypothesis(JsonRecord):
    SCHEMA = "route_hypothesis"
    hypothesis_id: str
    actor: str
    sink_ref: str
    boundary_id: str
    entrypoint_ref: str | None = None
    transformation_refs: tuple[str, ...] = ()
    control_refs: tuple[str, ...] = ()
    status: str = "hypothesis"
    proof_gaps: tuple[str, ...] = ("Static colocation does not prove data flow or reachability.",)


@dataclass(frozen=True)
class RepositoryThreatModel(JsonRecord):
    SCHEMA = "assurance_repository_threat_model"
    NESTED = {"inventory": RepositoryInventory, "draft": SecurityProfileDraft}
    MANY = {"routes": RouteHypothesis}
    model_id: str
    inventory: RepositoryInventory
    draft: SecurityProfileDraft
    actors: tuple[str, ...]
    routes: tuple[RouteHypothesis, ...] = ()
    counterevidence_refs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    open_questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.inventory.repository != self.draft.repository:
            raise ValueError("threat model repository mismatch")
        _unique(self.routes, "hypothesis_id")
        facts = {fact.fact_id: fact for fact in self.inventory.facts}
        boundaries = {boundary.id for boundary in self.draft.trust_boundaries}
        for route in self.routes:
            if (
                route.sink_ref not in facts
                or facts[route.sink_ref].kind != "sink"
                or (route.actor not in self.actors or route.boundary_id not in boundaries)
            ):
                raise ValueError("threat model route reference mismatch")
            if route.entrypoint_ref is not None and (
                route.entrypoint_ref not in facts
                or facts[route.entrypoint_ref].kind != "entrypoint"
            ):
                raise ValueError("threat model entrypoint reference mismatch")
            for refs, kind in (
                (route.transformation_refs, "transformation"),
                (route.control_refs, "control"),
            ):
                if any(ref not in facts or facts[ref].kind != kind for ref in refs):
                    raise ValueError("threat model control reference mismatch")
        if any(
            ref not in facts or facts[ref].kind != "control" for ref in self.counterevidence_refs
        ):
            raise ValueError("threat model counterevidence reference mismatch")
