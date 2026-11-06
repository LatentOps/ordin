"""Optional behavioral inference; signals never establish effects or authority."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
import hashlib
import hmac
import re
import secrets
from threading import Condition, RLock, Thread
import time
from typing import Any, Callable, Protocol
from uuid import uuid4

from ordin import ActionEnvelope
from ordin._runtime_json import canonical_json, digest

from .models import SwarmContext

SIGNAL_CLASSES = (
    "none",
    "unknown",
    "prompt_injection",
    "policy_persuasion",
    "task_redirection",
    "collusive_coordination",
    "evasive_retry",
    "coordinated_plan_change",
)
INPUT_KINDS = ("private_instruction", "untrusted_message", "tool_output", "shared_plan", "retry")
_PATTERNS = (
    (
        "prompt_injection",
        re.compile(
            r"\b(ignore|disregard|override)\b.{0,48}\b(previous|system|developer|instruction|policy)\b"
        ),
    ),
    (
        "policy_persuasion",
        re.compile(
            r"\b(already approved|approval is granted|operator approved|authorized by the operator)\b"
        ),
    ),
    (
        "task_redirection",
        re.compile(r"\b(instead of|abandon|forget)\b.{0,48}\b(task|goal|request)\b"),
    ),
    (
        "collusive_coordination",
        re.compile(
            r"\b(other agent|agent [a-z0-9]+|collude|coordinate)\b.{0,64}\b(bypass|hide|split|secret|evade)\b"
        ),
    ),
    (
        "evasive_retry",
        re.compile(
            r"\b(retry|try again|rename|rephrase|split)\b.{0,48}\b(block|denied|deny|filter|detect|limit)\b"
        ),
    ),
    (
        "coordinated_plan_change",
        re.compile(r"\b(change|replace|revise)\b.{0,48}\b(shared plan|all agents|team plan)\b"),
    ),
)
_SECRET = re.compile(
    r"(?i)(bearer\s{1,8}\S{1,16384}|(?:password|secret|token|api[_-]?key)\s{0,8}[:=]\s{0,8}\S{1,16384}|[\w.+-]{1,64}@[\w.-]{1,128}\.[a-z]{2,16})"
)


def _number(value: Any, name: str) -> None:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("invalid bounded risk " + name)


def _hex(value: Any) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(v not in "0123456789abcdef" for v in value)
    ):
        raise ValueError("risk digest required")


@dataclass(frozen=True, slots=True)
class SwarmRiskBudget:
    time_ms: int = 50
    cost_micros: int = 0

    def __post_init__(self):
        if type(self.time_ms) is not int or not 1 <= self.time_ms <= 1000:
            raise ValueError("risk time budget must be 1..1000 ms")
        if type(self.cost_micros) is not int or not 0 <= self.cost_micros <= 1000000:
            raise ValueError("invalid risk cost reservation")

    def as_dict(self):
        return {"time_ms": self.time_ms, "cost_micros": self.cost_micros}


@dataclass(frozen=True, slots=True)
class SwarmRiskInput:
    kind: str
    text: str = field(repr=False)

    def __post_init__(self):
        if (
            type(self.kind) is not str
            or self.kind not in INPUT_KINDS
            or type(self.text) is not str
            or len(self.text) > 16384
            or len(self.text.encode()) > 16384
        ):
            raise ValueError("bounded private/untrusted risk input required")


@dataclass(frozen=True, slots=True)
class SwarmRiskEvidencePointer:
    pointer: str
    input_kind: str
    features: tuple[str, ...]
    excerpt: str | None = field(default=None, repr=False)

    def as_dict(self):
        value: dict[str, Any] = {
            "pointer": self.pointer,
            "input_kind": self.input_kind,
            "features": list(self.features),
        }
        if self.excerpt is not None:
            value["excerpt"] = self.excerpt
        return value


@dataclass(frozen=True, slots=True)
class SwarmRiskContext:
    context_digest: str
    evidence: tuple[SwarmRiskEvidencePointer, ...]
    privacy_mode: str

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_risk_context.v1",
            "context_digest": self.context_digest,
            "evidence": [v.as_dict() for v in self.evidence],
            "privacy_mode": self.privacy_mode,
            "evidence_class": "untrusted_behavioral_input",
            "host_facts_included": False,
            "raw_payload_included": self.privacy_mode == "redacted_excerpt_opt_in",
            "residual_privacy_risk": "bounded_excerpt_may_contain_private_text"
            if self.privacy_mode == "redacted_excerpt_opt_in"
            else "feature_and_digest_metadata",
        }


def build_swarm_risk_context(
    inputs: tuple[SwarmRiskInput, ...],
    *,
    include_redacted_excerpt: bool = False,
    _pointer_key: bytes | None = None,
) -> SwarmRiskContext:
    """Explicit collection only. Default output contains no prompt or payload text."""
    if (
        type(inputs) is not tuple
        or len(inputs) > 16
        or any(type(v) is not SwarmRiskInput for v in inputs)
    ):
        raise ValueError("at most 16 explicit risk inputs required")
    if (
        type(include_redacted_excerpt) is not bool
        or sum(len(v.text.encode()) for v in inputs) > 65536
    ):
        raise ValueError("risk context capacity or excerpt opt-in invalid")
    refs = []
    key = _pointer_key if _pointer_key is not None else secrets.token_bytes(32)
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("original private risk pointer key required")
    for index, value in enumerate(inputs):
        value.__post_init__()
        normalized = " ".join(value.text.casefold().split())
        features = tuple(name for name, pattern in _PATTERNS if pattern.search(normalized))
        excerpt = _SECRET.sub("[redacted]", normalized)[:256] if include_redacted_excerpt else None
        refs.append(
            SwarmRiskEvidencePointer(
                hmac.new(
                    key,
                    str(index).encode() + value.kind.encode() + value.text.encode(),
                    hashlib.sha256,
                ).hexdigest(),
                value.kind,
                features,
                excerpt,
            )
        )
    mode = "redacted_excerpt_opt_in" if include_redacted_excerpt else "features_only"
    return SwarmRiskContext(digest([mode, [v.as_dict() for v in refs]]), tuple(refs), mode)


@dataclass(frozen=True, slots=True)
class SwarmRiskSignal:
    signal_class: str
    evidence_pointers: tuple[str, ...]
    confidence: float
    uncertainty: float
    reported_cost_micros: int
    budget: SwarmRiskBudget

    def __post_init__(self):
        if (
            type(self.signal_class) is not str
            or self.signal_class not in SIGNAL_CLASSES
            or type(self.evidence_pointers) is not tuple
            or len(self.evidence_pointers) > 16
        ):
            raise ValueError("invalid risk class or evidence pointers")
        if self.signal_class not in {"none", "unknown"} and not self.evidence_pointers:
            raise ValueError("positive risk inference requires original evidence pointers")
        for pointer in self.evidence_pointers:
            _hex(pointer)
        if len(set(self.evidence_pointers)) != len(self.evidence_pointers):
            raise ValueError("risk evidence pointers must be unique")
        _number(self.confidence, "confidence")
        _number(self.uncertainty, "uncertainty")
        if type(self.budget) is not SwarmRiskBudget:
            raise ValueError("typed risk budget required")
        self.budget.__post_init__()
        if (
            type(self.reported_cost_micros) is not int
            or not 0 <= self.reported_cost_micros <= self.budget.cost_micros
        ):
            raise ValueError("risk output exceeded cost reservation")

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_risk_signal.v1",
            "signal_class": self.signal_class,
            "evidence_pointers": list(self.evidence_pointers),
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "reported_cost_micros": self.reported_cost_micros,
            "budget": self.budget.as_dict(),
            "evidence_class": "behavioral_inference",
            "execution_authority": False,
            "verified_effects": False,
        }

    @classmethod
    def from_dict(cls, value):
        keys = {
            "schema_version",
            "signal_class",
            "evidence_pointers",
            "confidence",
            "uncertainty",
            "reported_cost_micros",
            "budget",
            "evidence_class",
            "execution_authority",
            "verified_effects",
        }
        if (
            type(value) is not dict
            or set(value) != keys
            or value["schema_version"] != "ordin.swarm_risk_signal.v1"
            or value["evidence_class"] != "behavioral_inference"
            or value["execution_authority"] is not False
            or value["verified_effects"] is not False
            or type(value["budget"]) is not dict
            or set(value["budget"]) != {"time_ms", "cost_micros"}
            or type(value["evidence_pointers"]) is not list
            or len(value["evidence_pointers"]) > 16
        ):
            raise ValueError("strict inference-only risk output required")
        return cls(
            value["signal_class"],
            tuple(value["evidence_pointers"]),
            value["confidence"],
            value["uncertainty"],
            value["reported_cost_micros"],
            SwarmRiskBudget(**value["budget"]),
        )


class SwarmRiskSignalProvider(Protocol):
    """Explicit host configured code; no discovery, download or built-in network."""

    def score(
        self, context: SwarmRiskContext, budget: SwarmRiskBudget
    ) -> SwarmRiskSignal | dict[str, Any]: ...


class LocalSwarmRiskRules:
    """Fixed offline heuristics. Confidence is uncalibrated, not prevention proof."""

    def score(self, context: SwarmRiskContext, budget: SwarmRiskBudget) -> SwarmRiskSignal:
        hits = [(feature, row.pointer) for row in context.evidence for feature in row.features]
        selected = hits[0][0] if hits else "none"
        pointers = tuple(dict.fromkeys(pointer for _, pointer in hits))
        return SwarmRiskSignal(
            selected, pointers, 0.6 if hits else 0.5, 0.4 if hits else 0.5, 0, budget
        )


@dataclass(frozen=True, slots=True, eq=False)
class SwarmRiskTicket:
    ticket_id: str


@dataclass(frozen=True, slots=True, eq=False)
class SwarmRiskReceipt:
    receipt_id: str
    status: str
    signal: SwarmRiskSignal | None
    context_digest: str
    action_digest: str
    input_digest: str
    provider_binding: str
    expires_at: float
    elapsed_ms: float
    reserved_cost_micros: int
    budget: SwarmRiskBudget
    privacy_mode: str

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_risk_receipt.v1",
            "receipt_id": self.receipt_id,
            "status": self.status,
            "signal": self.signal.as_dict() if self.signal else None,
            "context_digest": self.context_digest,
            "action_digest": self.action_digest,
            "input_digest": self.input_digest,
            "provider_binding": self.provider_binding,
            "expires_at": self.expires_at,
            "elapsed_ms": self.elapsed_ms,
            "reserved_cost_micros": self.reserved_cost_micros,
            "budget": self.budget.as_dict(),
            "privacy_mode": self.privacy_mode,
            "evidence_class": "behavioral_inference",
            "execution_authority": False,
            "verified_effects": False,
        }


@dataclass(frozen=True, slots=True)
class SwarmRiskPromotionPolicy:
    signal_classes: tuple[str, ...]
    disposition: str = "escalate"
    minimum_confidence: float = 0.6
    maximum_uncertainty: float = 0.4
    on_missing: str = "ignore"
    maximum_calibration_false_positive_rate: float = 1.0

    def __post_init__(self):
        if (
            type(self.signal_classes) is not tuple
            or not self.signal_classes
            or any(type(value) is not str for value in self.signal_classes)
            or len(set(self.signal_classes)) != len(self.signal_classes)
            or any(v not in SIGNAL_CLASSES[2:] for v in self.signal_classes)
            or type(self.disposition) is not str
            or self.disposition not in {"escalate", "deny"}
            or type(self.on_missing) is not str
            or self.on_missing not in {"ignore", "escalate", "deny"}
        ):
            raise ValueError("risk operator policy can only tighten a decision")
        for value, name in (
            (self.minimum_confidence, "confidence"),
            (self.maximum_uncertainty, "uncertainty"),
            (self.maximum_calibration_false_positive_rate, "false_positive_rate"),
        ):
            _number(value, name)


@dataclass(frozen=True, slots=True)
class SwarmRiskCalibrationCase:
    case_id: str
    inputs: tuple[SwarmRiskInput, ...] = field(repr=False)
    expected_class: str

    def __post_init__(self):
        if (
            type(self.case_id) is not str
            or not 1 <= len(self.case_id) <= 128
            or self.expected_class not in SIGNAL_CLASSES
            or self.expected_class == "unknown"
        ):
            raise ValueError("bounded synthetic calibration case required")
        build_swarm_risk_context(self.inputs)


@dataclass(frozen=True, slots=True, eq=False)
class SwarmRiskCalibrationReport:
    report_id: str
    provider_binding: str
    dataset_digest: str
    cases: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    exact_class_matches: int
    failures: int
    elapsed_ms: tuple[float, ...]
    confidence_brier_score: float = 0.0
    mean_uncertainty: float = 1.0
    class_confusion: tuple[tuple[str, str, int], ...] = ()

    @property
    def false_positive_rate(self):
        count = self.false_positive + self.true_negative
        return self.false_positive / count if count else 1.0

    def as_dict(self):
        return {
            "schema_version": "ordin.swarm_risk_calibration.v1",
            "report_id": self.report_id,
            "provider_binding": self.provider_binding,
            "dataset_digest": self.dataset_digest,
            "dataset_digest_kind": "private_scorer_hmac",
            "cases": self.cases,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "exact_class_matches": self.exact_class_matches,
            "failures": self.failures,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative / (self.false_negative + self.true_positive),
            "mean_elapsed_ms": sum(self.elapsed_ms) / len(self.elapsed_ms),
            "maximum_elapsed_ms": max(self.elapsed_ms),
            "confidence_brier_score": self.confidence_brier_score,
            "mean_uncertainty": self.mean_uncertainty,
            "class_confusion": [
                {"expected": expected, "predicted": predicted, "count": count}
                for expected, predicted, count in self.class_confusion
            ],
            "confidence_calibration": "measured_on_declared_synthetic_corpus_only",
            "data_scope": "caller_declared_synthetic_calibration",
            "authorization_tests_included": False,
            "general_prompt_injection_prevention": "not_established",
            "execution_authority": False,
        }


@dataclass
class _Job:
    context_digest: str
    action_digest: str
    context: SwarmRiskContext
    budget: SwarmRiskBudget
    started: float
    generation: int
    reserved_cost: int = 0
    receipt: SwarmRiskReceipt | None = None
    provider_call: Any = field(default=None, repr=False)
    ticket_id: str = ""


class SwarmRiskScorer:
    """Bounded shadow workers. A pure gate review never calls a classifier.

    An explicit semantic plugin is trusted host code, not an OS sandbox. A timed
    out worker retains its slot until it exits; late output is discarded. Cost
    reservation is admission accounting, not a guarantee about provider billing.
    """

    def __init__(
        self,
        provider: SwarmRiskSignalProvider | None = None,
        *,
        enabled: bool = False,
        operator: object,
        provider_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_pending: int = 2,
        max_jobs: int = 1024,
        total_cost_micros: int = 0,
        include_redacted_excerpt: bool = False,
    ):
        if (
            type(enabled) is not bool
            or type(operator) is not object
            or not callable(clock)
            or provider_id is not None
            and (type(provider_id) is not str or not 1 <= len(provider_id) <= 128)
            or type(max_pending) is not int
            or not 1 <= max_pending <= 8
            or type(max_jobs) is not int
            or not 1 <= max_jobs <= 4096
            or type(total_cost_micros) is not int
            or not 0 <= total_cost_micros <= 10**12
            or type(include_redacted_excerpt) is not bool
        ):
            raise ValueError("invalid protected bounded risk configuration")
        selected = provider if provider is not None else LocalSwarmRiskRules()
        provider_id = provider_id or (
            "local-fixed-rules-v1"
            if type(selected) is LocalSwarmRiskRules
            else "user-configured-semantic-provider"
        )
        provider_call = getattr(selected, "score", None) if enabled else None
        if enabled and not callable(provider_call):
            raise ValueError("explicit risk provider score interface required")
        self._provider, self._enabled, self._operator, self._clock = (
            selected,
            enabled,
            operator,
            clock,
        )
        self._id, self._pending_limit, self._job_limit, self._cost_limit = (
            provider_id,
            max_pending,
            max_jobs,
            total_cost_micros,
        )
        self._excerpt, self._nonce, self._generation, self._cost = (
            include_redacted_excerpt,
            uuid4().hex,
            0,
            0,
        )
        self._provider_call = provider_call
        self._original_provider, self._original_clock, self._original_call = (
            selected,
            clock,
            provider_call,
        )
        self._configuration_values = (
            enabled,
            provider_id,
            max_pending,
            max_jobs,
            total_cost_micros,
            include_redacted_excerpt,
        )
        self._jobs: dict[SwarmRiskTicket, _Job] = {}
        self._latest: dict[tuple[str, str], _Job] = {}
        self._active: set[SwarmRiskTicket] = set()
        self._receipts: dict[SwarmRiskReceipt, str] = {}
        self._reports: dict[SwarmRiskCalibrationReport, str] = {}
        self._promotion: SwarmRiskPromotionPolicy | None = None
        self._condition = Condition(RLock())
        self._pointer_key = secrets.token_bytes(32)
        self._last_now = 0.0

    def _configuration(self):
        if (
            self._provider is not self._original_provider
            or self._clock is not self._original_clock
            or self._provider_call is not self._original_call
            or (
                self._enabled,
                self._id,
                self._pending_limit,
                self._job_limit,
                self._cost_limit,
                self._excerpt,
            )
            != self._configuration_values
        ):
            raise ValueError("protected risk configuration changed")

    @property
    def enabled(self) -> bool:
        with self._condition:
            self._configuration()
            return self._enabled

    def _now(self) -> float:
        now = self._clock()
        if type(now) not in {int, float} or not math.isfinite(now) or now < self._last_now:
            raise ValueError("risk protected clock unavailable or moved backward")
        self._last_now = float(now)
        return float(now)

    @property
    def binding_digest(self):
        with self._condition:
            self._configuration()
            return digest(
                [
                    self._nonce,
                    self._id,
                    self._enabled,
                    self._generation,
                    self._excerpt,
                    self._configuration_values,
                    repr(self._promotion),
                ]
            )

    @property
    def promoting(self) -> bool:
        with self._condition:
            return self._enabled and self._promotion is not None

    def _receipt(self, job: _Job, status: str, signal=None):
        receipt = SwarmRiskReceipt(
            uuid4().hex,
            status,
            signal,
            job.context_digest,
            job.action_digest,
            job.context.context_digest,
            self.binding_digest,
            self._now() + 30,
            max(0, (time.monotonic() - job.started) * 1000),
            job.reserved_cost,
            job.budget,
            job.context.privacy_mode,
        )
        self._receipts[receipt] = digest(receipt.as_dict())
        job.receipt = receipt
        self._condition.notify_all()
        return receipt

    def submit(
        self,
        context: SwarmContext,
        action: ActionEnvelope,
        inputs: tuple[SwarmRiskInput, ...],
        *,
        budget: SwarmRiskBudget = SwarmRiskBudget(),
    ) -> SwarmRiskTicket | None:
        # Disabled means no input collection, hashing, worker, provider call or charge.
        with self._condition:
            self._configuration()
            if not self._enabled:
                return None
        if (
            type(context) is not SwarmContext
            or type(action) is not ActionEnvelope
            or type(budget) is not SwarmRiskBudget
        ):
            raise ValueError("exact risk action/context/budget required")
        budget.__post_init__()
        # Retain a protected value snapshot; provider/caller objects are not the
        # authoritative deadline or reservation after admission.
        budget = SwarmRiskBudget(budget.time_ms, budget.cost_micros)
        context_digest = digest(context.as_dict())
        pointer_key = hmac.new(
            self._pointer_key,
            b"ordin.swarm.risk.context.v1\0" + context_digest.encode("ascii"),
            hashlib.sha256,
        ).digest()
        redacted = build_swarm_risk_context(
            inputs, include_redacted_excerpt=self._excerpt, _pointer_key=pointer_key
        )
        with self._condition:
            self._configuration()
            self._now()
            action_digest = digest(action.as_dict())
            if len(self._jobs) >= self._job_limit:
                # A rejected fresh capture must not leave an older benign
                # inference current for this action. Dropping the existing
                # index needs no extra history capacity or worker admission.
                self._latest.pop((context_digest, action_digest), None)
                raise ValueError("risk bounded job history capacity reached")
            ticket = SwarmRiskTicket(uuid4().hex)
            job = _Job(
                context_digest,
                action_digest,
                redacted,
                budget,
                time.monotonic(),
                self._generation,
            )
            self._jobs[ticket] = job
            job.provider_call = self._provider_call
            job.ticket_id = ticket.ticket_id
            self._latest[(job.context_digest, job.action_digest)] = job
            if (
                len(self._active) >= self._pending_limit
                or self._cost + budget.cost_micros > self._cost_limit
            ):
                self._receipt(job, "budget_exhausted")
                return ticket
            self._cost += budget.cost_micros
            job.reserved_cost = budget.cost_micros
            self._active.add(ticket)
            try:
                Thread(
                    target=self._score, args=(ticket, job), name="ordin-risk-shadow", daemon=True
                ).start()
            except RuntimeError:
                self._active.discard(ticket)
                self._receipt(job, "failed")
            return ticket

    def _score(self, ticket, job):
        signal, status = None, "failed"
        try:
            # Frozen dataclasses are not a sandbox for configured Python code.
            # A provider receives detached data, never the retained scope/budget
            # against which its output and deadline will be checked.
            supplied = SwarmRiskContext(
                job.context.context_digest,
                tuple(
                    SwarmRiskEvidencePointer(row.pointer, row.input_kind, row.features, row.excerpt)
                    for row in job.context.evidence
                ),
                job.context.privacy_mode,
            )
            supplied_budget = SwarmRiskBudget(job.budget.time_ms, job.budget.cost_micros)
            result = job.provider_call(supplied, supplied_budget)
            signal = SwarmRiskSignal.from_dict(
                result.as_dict() if type(result) is SwarmRiskSignal else result
            )
            if signal.budget != job.budget or not set(signal.evidence_pointers) <= {
                row.pointer for row in job.context.evidence
            }:
                raise ValueError("classifier output changed original budget or evidence scope")
            status = "scored"
        except Exception:
            signal = None
        finally:
            with self._condition:
                self._active.discard(ticket)
                if job.receipt is None:
                    if (time.monotonic() - job.started) * 1000 > job.budget.time_ms:
                        status, signal = "timeout", None
                    if job.generation != self._generation:
                        status, signal = "stale", None
                    self._receipt(job, status, signal)
                self._condition.notify_all()

    def poll(self, ticket: SwarmRiskTicket | None, *, wait_ms: int = 0) -> SwarmRiskReceipt | None:
        if ticket is None and not self._enabled:
            return None
        if type(wait_ms) is not int or not 0 <= wait_ms <= 1000:
            raise ValueError("bounded risk polling wait required")
        with self._condition:
            self._configuration()
            if type(ticket) is not SwarmRiskTicket or ticket not in self._jobs:
                raise ValueError("original risk shadow ticket required")
            job = self._jobs[ticket]
            if ticket.ticket_id != job.ticket_id:
                raise ValueError("mutated risk shadow ticket")
            remaining = job.budget.time_ms / 1000 - (time.monotonic() - job.started)
            if job.receipt is None and wait_ms and remaining > 0:
                self._condition.wait_for(
                    lambda: job.receipt is not None, min(wait_ms / 1000, remaining)
                )
            if (
                job.receipt is None
                and (time.monotonic() - job.started) * 1000 >= job.budget.time_ms
            ):
                self._receipt(job, "timeout")
            return job.receipt

    def verify(self, receipt, context: SwarmContext, action: ActionEnvelope):
        with self._condition:
            try:
                self._configuration()
                return (
                    type(receipt) is SwarmRiskReceipt
                    and self._receipts.get(receipt) == digest(receipt.as_dict())
                    and receipt.provider_binding == self.binding_digest
                    and receipt.context_digest == digest(context.as_dict())
                    and receipt.action_digest == digest(action.as_dict())
                    and self._latest.get((receipt.context_digest, receipt.action_digest))
                    is not None
                    and self._latest[(receipt.context_digest, receipt.action_digest)].receipt
                    is receipt
                    and self._now() < receipt.expires_at
                )
            except (ValueError, AttributeError, TypeError):
                return False

    def project(self, receipt, context: SwarmContext, action: ActionEnvelope):
        with self._condition:
            policy = self._promotion
            if not self._enabled or policy is None:
                return "execute", ()
            if not self.verify(receipt, context, action) or receipt.status != "scored":
                return ("execute" if policy.on_missing == "ignore" else policy.on_missing), (
                    "risk.signal_missing_or_unverified",
                )
            signal = receipt.signal
            if (
                signal is None
                or signal.signal_class == "unknown"
                or (
                    signal.signal_class in policy.signal_classes
                    and (
                        signal.confidence < policy.minimum_confidence
                        or signal.uncertainty > policy.maximum_uncertainty
                    )
                )
            ):
                return ("execute" if policy.on_missing == "ignore" else policy.on_missing), (
                    "risk.inference_inconclusive",
                )
            if (
                signal is not None
                and signal.signal_class in policy.signal_classes
                and signal.confidence >= policy.minimum_confidence
                and signal.uncertainty <= policy.maximum_uncertainty
            ):
                return policy.disposition, ("risk.operator_inference_threshold",)
            return "execute", ()

    def calibrate(
        self,
        cases: tuple[SwarmRiskCalibrationCase, ...],
        *,
        budget: SwarmRiskBudget,
        context: SwarmContext,
        action: ActionEnvelope,
    ) -> SwarmRiskCalibrationReport:
        if (
            not self._enabled
            or type(context) is not SwarmContext
            or type(action) is not ActionEnvelope
            or type(budget) is not SwarmRiskBudget
            or type(cases) is not tuple
            or not 12 <= len(cases) <= 256
            or any(type(v) is not SwarmRiskCalibrationCase for v in cases)
            or len({v.case_id for v in cases}) != len(cases)
            or not any(v.expected_class == "none" for v in cases)
            or not any(v.expected_class not in {"none", "unknown"} for v in cases)
        ):
            raise ValueError("explicit independent synthetic positive/benign calibration required")
        with self._condition:
            if len(self._reports) >= 16:
                raise ValueError("risk calibration history capacity reached")
            binding = self.binding_digest
        # Calibration is an independent synthetic capture, never a replacement
        # for the latest evidence attached to a caller's live action.
        calibration_action = replace(action, action_id="risk-calibration-" + uuid4().hex)
        tp = fp = tn = fn = matches = failures = 0
        elapsed, fingerprints = [], []
        brier: list[float] = []
        uncertainties: list[float] = []
        confusion: dict[tuple[str, str], int] = {}
        for case in cases:
            case.__post_init__()
            ticket = self.submit(context, calibration_action, case.inputs, budget=budget)
            receipt = self.poll(ticket, wait_ms=budget.time_ms)
            if receipt is None:
                raise ValueError("risk calibration result unavailable")
            predicted = (
                receipt.signal.signal_class
                if receipt.status == "scored" and receipt.signal
                else "unknown"
            )
            expected_positive = case.expected_class != "none"
            predicted_positive = predicted not in {"none", "unknown"}
            tp += int(expected_positive and predicted_positive)
            fp += int(not expected_positive and predicted_positive)
            tn += int(not expected_positive and predicted == "none")
            fn += int(expected_positive and not predicted_positive)
            matches += int(predicted == case.expected_class)
            failures += int(receipt.status != "scored" or predicted == "unknown")
            confidence = receipt.signal.confidence if receipt.signal else 0.5
            probability = confidence if predicted_positive else 1 - confidence
            brier.append((probability - int(expected_positive)) ** 2)
            uncertainties.append(receipt.signal.uncertainty if receipt.signal else 1.0)
            confusion[case.expected_class, predicted] = (
                confusion.get((case.expected_class, predicted), 0) + 1
            )
            elapsed.append(receipt.elapsed_ms)
            fingerprints.append(
                [
                    case.case_id,
                    receipt.input_digest,
                    case.expected_class,
                ]
            )
        report = SwarmRiskCalibrationReport(
            uuid4().hex,
            binding,
            hmac.new(
                self._pointer_key, canonical_json(fingerprints).encode("utf-8"), hashlib.sha256
            ).hexdigest(),
            len(cases),
            tp,
            fp,
            tn,
            fn,
            matches,
            failures,
            tuple(elapsed),
            sum(brier) / len(brier),
            sum(uncertainties) / len(uncertainties),
            tuple(
                (expected, predicted, count)
                for (expected, predicted), count in sorted(confusion.items())
            ),
        )
        with self._condition:
            if binding != self.binding_digest:
                raise ValueError("risk provider configuration changed during calibration")
            if len(self._reports) >= 16:
                raise ValueError("risk calibration history capacity reached")
            self._reports[report] = digest(report.as_dict())
        return report

    def configure_promotion(
        self,
        policy: SwarmRiskPromotionPolicy | None,
        report: SwarmRiskCalibrationReport,
        *,
        operator: object,
    ):
        if (
            operator is not self._operator
            or policy is not None
            and type(policy) is not SwarmRiskPromotionPolicy
        ):
            raise ValueError("original protected risk operator policy required")
        with self._condition:
            if (
                type(report) is not SwarmRiskCalibrationReport
                or self._reports.get(report) != digest(report.as_dict())
                or report.provider_binding != self.binding_digest
            ):
                raise ValueError("original current independent calibration report required")
            if policy is not None:
                policy.__post_init__()
                if report.failures:
                    raise ValueError("incomplete risk calibration cannot enable promotion")
                if report.false_positive_rate > policy.maximum_calibration_false_positive_rate:
                    raise ValueError("risk calibration exceeds operator false-positive maximum")
            self._promotion, self._generation = (
                (replace(policy) if policy is not None else None),
                self._generation + 1,
            )

    def disable_promotion(self, *, operator: object) -> None:
        """An original operator can stop tightening when calibration is unavailable."""
        if operator is not self._operator:
            raise ValueError("original protected risk operator required")
        with self._condition:
            self._promotion = None
            self._generation += 1
            self._condition.notify_all()

    def record_diagnostic(
        self,
        receipt,
        context,
        action,
        *,
        source,
        channel,
        adapter,
        operator: object,
        severity: str = "unknown",
    ) -> None:
        """Explicitly queue original inference as a #275 diagnostic, never host evidence.

        This performs no collection or scoring. The caller checks the source's
        flush/checkpoint when durable diagnostic acknowledgement is needed.
        """
        if not self.enabled:
            return
        from .diagnostics import SwarmAuditSource

        if operator is not self._operator or type(source) is not SwarmAuditSource:
            raise ValueError("original scoped risk diagnostic source and operator required")
        source._check(operator)
        native_scope = source._coordinator._scope(source._scope)
        if (
            type(context) is not SwarmContext
            or (
                context.identity.tenant_id,
                context.identity.swarm_id,
                context.identity.task_id,
            )
            != native_scope.authenticator._scope
        ):
            raise ValueError("risk diagnostic belongs to another task scope")
        source._registry.authenticate(context, channel, adapter)
        if not self.verify(receipt, context, action):
            raise ValueError("original current scoped risk receipt required")
        source.record_risk(
            severity=severity if receipt.signal is not None else "unknown",
            confidence=receipt.signal.confidence if receipt.signal is not None else 0.0,
            model_ref="risk-" + digest(receipt.as_dict()),
            action_ref=receipt.action_digest,
            operator=operator,
        )

    def status(self):
        with self._condition:
            return {
                "enabled": self._enabled,
                "provider_id": self._id,
                "active_workers": len(self._active),
                "retained_jobs": len(self._jobs),
                "maximum_workers": self._pending_limit,
                "reserved_cost_micros": self._cost,
                "maximum_cost_micros": self._cost_limit,
                "physical_billing_enforcement": False,
                "promotion_configured": self._promotion is not None,
                "execution_authority": False,
                "privacy_mode": "redacted_excerpt_opt_in" if self._excerpt else "features_only",
            }
