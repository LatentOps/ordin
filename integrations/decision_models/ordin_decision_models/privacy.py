"""Explicit protected source selection; no raw action/history forwarding."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from dataclasses import dataclass, field

from ordin.assurance import (
    AssuranceDecision,
    AssuranceGate,
    AssuranceHostContext,
    InstructionOrigin,
    SourceUse,
)
from ordin.assurance._json import digest, validate
from ordin.assurance.models import JsonRecord
from ordin._runtime_json import digest as core_digest

INSPECTION_REASONS = (
    "ambiguous_task_alignment",
    "unclear_effect",
    "near_trust_boundary",
    "cross_agent_flow",
)


@dataclass(frozen=True)
class _InspectionSeal:
    payload_digest: str


@dataclass(frozen=True)
class HostSemanticInspection(JsonRecord):
    SCHEMA = "assurance_semantic_inspection"
    source_key: str
    action_digest: str
    reasons: tuple[str, ...]
    _seal: _InspectionSeal | None = field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self):
        super().__post_init__()
        if (
            len(set(self.reasons)) != len(self.reasons)
            or not isinstance(self._seal, _InspectionSeal)
            or self._seal.payload_digest != self.digest
        ):
            raise ValueError("semantic inspection requires a protected action-bound host request")

    @classmethod
    def from_dict(cls, payload):
        raise ValueError("JSON/agent statements cannot authenticate an inspection trigger")


def request_semantic_inspection(
    source, action, *, reasons: tuple[str, ...]
) -> HostSemanticInspection:
    from ordin.assurance import HostEvidenceSource
    from ordin import ActionEnvelope

    if not isinstance(source, HostEvidenceSource) or not isinstance(action, ActionEnvelope):
        raise ValueError(
            "semantic inspection trigger requires protected host and normalized action"
        )
    values: dict[str, Any] = dict(
        source_key=source.key, action_digest=core_digest(action.as_dict()), reasons=reasons
    )
    preview = object.__new__(HostSemanticInspection)
    for key, value in values.items():
        object.__setattr__(preview, key, value)
    validate(preview.SCHEMA, preview.as_dict())
    return HostSemanticInspection(**values, _seal=_InspectionSeal(preview.digest))


from ordin.assurance.origins import verify_source_use
from ordin.action import ActionHistory

from .protocol import SanitizedDecisionState, _issue_state

_SECRET = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b|\b(?:authorization\s*[:=]\s*bearer\s+\S+|(?:api[_-]?key|token|password|secret|credential)\s*[:=]\s*[^\s,;]+)|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|https?://[^\s/@]+:[^\s/@]+@)"
)
_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


@dataclass(frozen=True)
class SelectedSnippet:
    """Selected actual bytes plus protected source/use handles; never just text."""

    origin: InstructionOrigin = field(repr=False)
    use: SourceUse = field(repr=False)
    text: str = field(repr=False)


def _text(value: str, maximum: int) -> tuple[str, bool]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum or _UNSAFE.search(value):
        raise ValueError("selected semantic content encoding/size unsupported")
    detected = _SECRET.search(value) is not None
    cleaned = "[redacted-sensitive-content]" if detected else value
    return " ".join(cleaned.split()), detected


def sanitize_decision_state(
    gate: AssuranceGate,
    decision: AssuranceDecision,
    *,
    host_context: AssuranceHostContext | None = None,
    history: ActionHistory | None = None,
    task_origin: InstructionOrigin | None = None,
    task_text: str | None = None,
    snippets: tuple[SelectedSnippet, ...] = (),
    inspection: HostSemanticInspection | None = None,
) -> SanitizedDecisionState:
    if (
        not isinstance(gate, AssuranceGate)
        or not isinstance(decision, AssuranceDecision)
        or not gate.binding_matches(
            decision, decision.review.action, host_context=host_context, history=history
        )
    ):
        raise ValueError(
            "semantic input requires a current action/profile/history-bound gate review"
        )
    if not isinstance(snippets, tuple) or len(snippets) > 4:
        raise ValueError("semantic snippet selection must be bounded")
    if (task_origin is None) != (task_text is None):
        raise ValueError("trusted task requires protected origin and exact text")
    host = host_context.source if isinstance(host_context, AssuranceHostContext) else None
    task = None
    task_hash = None
    remote = True
    signals: set[str] = set()
    if inspection is not None:
        if (
            not isinstance(inspection, HostSemanticInspection)
            or host is None
            or inspection.source_key != host.key
            or inspection.action_digest != decision.action_digest
        ):
            raise ValueError(
                "semantic inspection trigger is stale, caller-supplied or from another host"
            )
        signals.update(inspection.reasons)
    if task_origin is not None:
        if (
            host is None
            or not isinstance(task_origin, InstructionOrigin)
            or task_origin.source_key != host.key
            or task_origin.kind != "authorized_user"
        ):
            raise ValueError("task context cannot be authenticated by caller role labels")
        assert task_text is not None
        raw = task_text.encode("utf-8")
        if (
            hashlib.sha256(raw).hexdigest() != task_origin.content_digest
            or task_origin.span_start != 0
            or task_origin.span_end != len(raw)
        ):
            raise ValueError("trusted task bytes changed or are incomplete")
        task, sensitive = _text(task_text, 2048)
        task_hash = task_origin.digest
        remote &= not sensitive and task_origin.classification == "public"
        if sensitive:
            signals.add("sensitive_content_redacted")
    selected = []
    for snippet in snippets:
        if (
            host is None
            or not isinstance(snippet, SelectedSnippet)
            or not verify_source_use(host, snippet.origin, snippet.use, decision.review.action)
        ):
            raise ValueError(
                "semantic snippet requires matching protected source/action correlation"
            )
        if hashlib.sha256(snippet.text.encode("utf-8")).hexdigest() != snippet.use.value_digest:
            raise ValueError("semantic selected bytes differ from actual action argument")
        text, sensitive = _text(snippet.text, 1024)
        if snippet.origin.classification == "secret":
            text = "[private-content-omitted]"
        remote &= not sensitive and snippet.origin.classification == "public"
        if snippet.origin.kind != "authorized_user":
            signals.add("untrusted_content_present")
        if snippet.use.usage == "instruction_context" and snippet.origin.kind != "authorized_user":
            signals.add("untrusted_instruction_context")
        if sensitive:
            signals.add("sensitive_content_redacted")
        if snippet.origin.classification in {"sensitive", "secret"}:
            signals.add("sensitive_source_present")
        selected.append(
            {
                "text": text,
                "origin_kind": snippet.origin.kind,
                "classification": snippet.origin.classification,
                "content_digest": hashlib.sha256(snippet.text.encode("utf-8")).hexdigest(),
            }
        )
    effects = tuple(decision.as_dict()["baseline"]["effects"])
    if any(effect.startswith("network.") for effect in effects):
        signals.add("network_effect")
    if any(
        effect
        in {
            "filesystem.permission_change",
            "privilege.escalation",
            "credential.read",
            "credential.write",
        }
        for effect in effects
    ):
        signals.add("authority_change_candidate")
    if any(effect.startswith("delegation.") for effect in effects):
        signals.add("delegation_candidate")
    if host_context is not None and any(
        assessment.kind == "delegated_authority_subset"
        and assessment.action_digest == decision.action_digest
        for assessment in host_context.assessments
    ):
        signals.add("delegation_candidate")
    if (
        task
        and selected
        and (
            signals.intersection(
                {
                    "ambiguous_task_alignment",
                    "unclear_effect",
                    "near_trust_boundary",
                    "untrusted_instruction_context",
                }
            )
            or decision.review.risk in {"medium", "high", "critical", "unknown"}
        )
    ):
        signals.add("task_alignment_question")
    if "cross_agent_flow" in signals:
        signals.add("delegation_candidate")
    kind = decision.review.action.kind
    kind = (
        kind
        if kind in {"shell", "tool", "mcp", "http", "filesystem", "process", "unknown"}
        else "unknown"
    )
    return _issue_state(
        action_digest=decision.action_digest,
        baseline_evidence_digest=decision.evidence_digest,
        gate_configuration_digest=gate.configuration_digest,
        host_context_digest=host_context.digest if host_context else None,
        host_source_key=host.key if host else None,
        task_context_digest=task_hash,
        action_kind=kind,
        risk=decision.review.risk,
        effects=effects,
        authorized_task=task,
        snippets=tuple(selected),
        signals=tuple(sorted(signals)),
        remote_eligible=remote,
        omitted_fields=len(decision.review.action.parameters),
    )
