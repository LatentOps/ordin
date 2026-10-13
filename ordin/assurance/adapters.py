"""Compose Assurance with existing host adapters and their IntegrationSession."""

from typing import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from ordin import AgentGate, AgentDecision, ActionEnvelope, ActionHistory

from .gate import AssuranceGate
from .host import HostEvidenceSource
from ._json import digest


@dataclass(frozen=True, init=False, kw_only=True)
class AssuranceAdapterGate(AgentGate):
    """Deterministic synchronous composition; no semantic provider is invoked.

    Inject this gate into existing Claude/Codex/Cursor/MCP integration objects.
    Hooks retain their own wire format and whether escalation can be approved.
    The protected host supplies source/receipt objects, never hook JSON labels.
    """

    assurance: AssuranceGate
    source: HostEvidenceSource
    _options: Mapping = field(repr=False, compare=False)
    _initial_configuration: str = field(repr=False, compare=False)
    _context_digest: str = field(repr=False, compare=False)

    def __init__(
        self, assurance: AssuranceGate, source: HostEvidenceSource, *, context_options=None
    ):
        if not isinstance(assurance, AssuranceGate) or not isinstance(source, HostEvidenceSource):
            raise ValueError(
                "adapter composition needs an actual Assurance gate and protected host source"
            )
        if assurance.approved_profile is not None:
            source._check_profile(assurance.approved_profile)
        options = {} if context_options is None else dict(context_options)
        if set(options) - {
            "capability_authorities",
            "request_authorities",
            "approvals",
            "assessments",
            "credential_uses",
        }:
            raise ValueError("adapter context options contain unsupported authority inputs")
        # Validate protected facts immediately and retain their immutable typed
        # collections. No callback from untrusted input or provider is accepted.
        initial_context = source.context(**options)
        object.__setattr__(self, "ordin", assurance.ordin)
        object.__setattr__(self, "assurance", assurance)
        object.__setattr__(self, "source", source)
        object.__setattr__(
            self,
            "_options",
            MappingProxyType({key: getattr(initial_context, key) for key in options}),
        )
        object.__setattr__(self, "_initial_configuration", assurance.configuration_digest)
        object.__setattr__(self, "_context_digest", initial_context.digest)

    @property
    def session_configuration_binding(self):
        return {
            "namespace": "ordin.assurance.adapter.v1",
            "configuration_digest": digest(
                "adapter_assurance_configuration",
                {"assurance": self.assurance.configuration_digest, "context": self._context_digest},
            ),
            "source_digest": self.source.key,
        }

    def evaluate_action(self, action, *, history=None, **kwargs) -> AgentDecision:
        if self.assurance.configuration_digest != self._initial_configuration:
            raise ValueError("Assurance configuration changed; create a fresh host gate/session")
        typed_history = (
            ActionHistory.from_dict(
                history.as_dict() if isinstance(history, ActionHistory) else history
            )
            if history is not None
            else None
        )
        if not isinstance(action, (ActionEnvelope, Mapping)):
            raise ValueError("adapter action must be a typed or bounded action proposal")
        context = self.source.context(history=typed_history, **self._options)
        decision = self.assurance.evaluate_action(
            action, history=typed_history, host_context=context, **kwargs
        )
        return AgentDecision(decision.disposition, decision.review)

    def evaluate(self, command, *, intent=None, context=None, trace=None):
        if trace is not None:
            raise ValueError("Assurance adapter uses generic action/history APIs for trace binding")
        return self.evaluate_action(ActionEnvelope.shell(command, intent=intent, context=context))
