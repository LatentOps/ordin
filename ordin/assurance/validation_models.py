"""Finding review and validation receipts; decoding never supplies proof."""

from dataclasses import dataclass, field

from .models import JsonRecord, RepositoryScope, SourceReference, EvidenceLink


@dataclass(frozen=True)
class FindingRubric(JsonRecord):
    SCHEMA = "finding_rubric"
    MANY = {
        "controlled_sources": SourceReference,
        "source_to_sink": SourceReference,
        "existing_controls": SourceReference,
    }
    actor: str
    controlled_sources: tuple[SourceReference, ...]
    allowed_permissions: tuple[str, ...]
    invariant_id: str
    expected_authority_digest: str
    source_to_sink: tuple[SourceReference, ...]
    existing_controls: tuple[SourceReference, ...] = ()
    preconditions: tuple[str, ...] = ()
    changes: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ValidationAuthority:
    payload_digest: str


@dataclass(frozen=True)
class FindingReview(JsonRecord):
    SCHEMA = "assurance_finding_review"
    NESTED = {"repository": RepositoryScope, "rubric": FindingRubric}
    MANY = {
        "verified_sources": SourceReference,
        "evidence": EvidenceLink,
        "counterevidence": EvidenceLink,
    }
    finding_digest: str
    repository: RepositoryScope
    rubric: FindingRubric
    source_snapshot_digest: str
    verified_sources: tuple[SourceReference, ...]
    evidence: tuple[EvidenceLink, ...]
    counterevidence: tuple[EvidenceLink, ...]
    proof_gaps: tuple[str, ...]
    status: str
    advisory_only: bool = True
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("finding review requires actual source inspection")
        if self.status == "reviewed" and self.proof_gaps:
            raise ValueError("finding review with source gaps cannot be complete")

    def public_dict(self):
        return {
            "schema_version": "ordin.assurance_finding_review_summary.v1",
            "report_digest": self.digest,
            "finding_digest": self.finding_digest,
            "repository_digest": self.repository.digest,
            "rubric_digest": self.rubric.digest,
            "source_snapshot_digest": self.source_snapshot_digest,
            "verified_source_digests": [source.digest for source in self.verified_sources],
            "evidence_digests": [link.digest for link in self.evidence],
            "counterevidence_digests": [link.digest for link in self.counterevidence],
            "proof_gaps": list(self.proof_gaps),
            "status": self.status,
            "advisory_only": True,
        }


@dataclass(frozen=True)
class HostContractAuthorization(JsonRecord):
    """Protected backend fact; generic completion/allowance cannot supply it."""

    SCHEMA = "assurance_contract_authorization"
    NESTED = {"repository": RepositoryScope}
    source_key: str
    runtime_source_key: str
    observation_digest: str
    contract_digest: str
    repository: RepositoryScope
    authorization_scope: str = "entire_contract"
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError(
                "contract authorization requires a protected actual backend grant fact"
            )


@dataclass(frozen=True)
class FindingValidation(JsonRecord):
    SCHEMA = "assurance_finding_validation"
    NESTED = {"repository": RepositoryScope, "fixture_source": SourceReference}
    MANY = {"evidence": EvidenceLink, "counterevidence": EvidenceLink}
    validation_id: str
    finding_digest: str
    review_digest: str
    repository: RepositoryScope
    mode: str
    result: str
    invariant_id: str
    boundary_digest: str
    action_digest: str | None
    action_kind: str | None
    fixture_digest: str | None
    fixture_source: SourceReference | None
    configuration_digest: str | None
    evidence: tuple[EvidenceLink, ...]
    counterevidence: tuple[EvidenceLink, ...]
    proof_gaps: tuple[str, ...]
    safe_reproducer_ref: str | None
    tested_scope: str
    contract_authorization_digest: str | None
    limitations: tuple[str, ...]
    source_key: str
    advisory_only: bool = True
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("finding validation requires an actual verified receipt")
        if self.result != "inconclusive" and (
            self.proof_gaps
            or self.mode == "static"
            or not self.action_digest
            or not self.fixture_digest
            or self.fixture_source is None
            or not self.configuration_digest
        ):
            raise ValueError("finding closure requires matching reproducible evidence without gaps")
        if self.result == "confirmed" and not self.evidence:
            raise ValueError("confirmation requires affirmative reproduction evidence")
        if (
            self.result == "confirmed"
            and self.mode == "host_observation"
            and self.contract_authorization_digest is None
        ):
            raise ValueError("host confirmation requires the exact actual grant receipt")
        if self.result == "refuted" and not self.counterevidence:
            raise ValueError("refutation requires decisive scoped counterevidence")

    def public_dict(self):
        from ._json import digest

        result = self.as_dict()
        result["repository"] = self.repository.digest
        result["fixture_source"] = self.fixture_source.digest if self.fixture_source else None
        result["invariant_id"] = digest("validation_invariant", self.invariant_id)
        result["action_kind"] = (
            digest("validation_action_kind", self.action_kind) if self.action_kind else None
        )
        result["safe_reproducer_ref"] = (
            digest("validation_reproducer", self.safe_reproducer_ref)
            if self.safe_reproducer_ref
            else None
        )
        for field_name in ("evidence", "counterevidence"):
            result[field_name] = [
                digest("validation_evidence", item) for item in result[field_name]
            ]
        result["schema_version"] = "ordin.assurance_finding_validation_summary.v1"
        result["report_digest"] = self.digest
        return result
