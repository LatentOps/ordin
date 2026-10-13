"""Model predictions may add escalation; they cannot remove any restriction."""

from __future__ import annotations

from dataclasses import dataclass, field

from ordin.assurance.gate import AssuranceDecision, DISPOSITION_ORDER
from ordin.assurance.models import JsonRecord, ModelRiskEvidence


@dataclass(frozen=True)
class _SemanticSeal:
    payload_digest: str


@dataclass(frozen=True)
class SemanticDecision(JsonRecord):
    SCHEMA = "assurance_semantic_decision"
    NESTED = {"model_evidence": ModelRiskEvidence}
    decision_id: str
    mode: str
    disposition: str
    baseline_disposition: str
    baseline_evidence_digest: str
    router_configuration_digest: str
    state_digest: str | None
    question_set_digest: str | None
    model_evidence: ModelRiskEvidence | None
    model_invoked: bool
    mandatory: bool
    uncertain_question_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    elapsed_ms: float
    advisory_only: bool = True
    _baseline: AssuranceDecision | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )
    _seal: _SemanticSeal | None = field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._baseline, AssuranceDecision)
            or self.baseline_evidence_digest != self._baseline.evidence_digest
            or self.baseline_disposition != self._baseline.disposition
        ):
            raise ValueError("semantic decision requires exact current baseline evidence")
        if DISPOSITION_ORDER[self.disposition] < DISPOSITION_ORDER[self.baseline_disposition]:
            raise ValueError("semantic evidence cannot downgrade deterministic restrictions")
        if self.mode in {"disabled", "shadow"} and self.disposition != self.baseline_disposition:
            raise ValueError("disabled/shadow semantic evidence cannot alter disposition")
        if not isinstance(self._seal, _SemanticSeal) or self._seal.payload_digest != self.digest:
            raise ValueError("semantic result requires a router-issued seal")

    @property
    def review(self):
        assert self._baseline is not None
        return self._baseline.review

    @property
    def may_execute(self):
        return self.disposition == "execute"

    @property
    def requires_approval(self):
        return self.disposition == "escalate"

    @property
    def denied(self):
        return self.disposition == "deny"

    @classmethod
    def from_dict(cls, payload):
        raise ValueError("JSON/model output cannot create a current semantic gate result")


def issue_semantic_decision(baseline, **values):
    preview = object.__new__(SemanticDecision)
    for key, value in {
        **values,
        "advisory_only": True,
        "_baseline": baseline,
        "_seal": None,
    }.items():
        object.__setattr__(preview, key, value)
    return SemanticDecision(**values, _baseline=baseline, _seal=_SemanticSeal(preview.digest))
