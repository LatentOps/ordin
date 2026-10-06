"""Bounded, explicitly owned state at an integration's execution boundary."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from . import __version__
from ._private_storage import MAX_DATABASE_BYTES, private_database
from .action import MAX_ACTION_HISTORY, ActionEnvelope, ActionHistory, ActionReview
from .agent import AgentDecision, AgentGate
from .execution import ActionObservation, ObservationHistory
from .mcp_contracts import MCPContractCheck
from .schema import validate_named_schema
from .temporal import default_temporal_policy
from .runtime_contract import RuntimeCapabilityContract, derive_runtime_capability_contract
from .runtime_observation import (
    RuntimeCorrelationError,
    RuntimeEvidenceSource,
    RuntimeObservation,
    RuntimeObservationHistory,
    RuntimeReviewBinding,
)
from ._runtime_json import validate as validate_runtime


SESSION_SCHEMA_VERSION = "ordin.integration_session.v1"
MAX_SESSION_BYTES = 1_048_576
MAX_SESSIONS = 64


def _json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("session state must contain bounded, finite JSON") from exc


def _digest(payload: Any) -> str:
    return hashlib.sha256(_json(payload).encode()).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate session JSON member")
        result[key] = value
    return result


def _load(text: str) -> dict[str, Any]:
    if len(text.encode()) > MAX_SESSION_BYTES:
        raise ValueError("session state exceeds its byte limit")
    try:
        payload = json.loads(text, object_pairs_hook=_unique)
        _json(payload)
    except (ValueError, RecursionError) as exc:
        raise ValueError("invalid session state JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("session state must be an object")
    pending = [(payload, 0)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, (dict, list)):
            if depth > 32:
                raise ValueError("session state nesting exceeds its limit")
            pending.extend(
                (value, depth + 1) for value in (item.values() if isinstance(item, dict) else item)
            )
    return payload


@dataclass(frozen=True)
class SessionIdentity:
    runtime: str
    session_id: str
    server: str | None = None

    def __post_init__(self) -> None:
        for value in (self.runtime, self.session_id):
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ValueError("session runtime and identity must be bounded non-empty text")
        if self.server is not None and (
            not isinstance(self.server, str) or not self.server.strip() or len(self.server) > 4096
        ):
            raise ValueError("session server must be bounded non-empty text")

    def as_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "session_id_sha256": hashlib.sha256(self.session_id.encode()).hexdigest(),
            "server": self.server,
        }

    @property
    def key(self) -> str:
        return _digest(self.as_dict())


def configuration_digest(gate: AgentGate) -> str:
    """Bind stored history to the evaluator version and reviewed configuration."""
    ordin = gate.ordin
    semantics = ordin.tool_semantics
    temporal = ordin.temporal_policy or default_temporal_policy()
    action_policy: Any = getattr(ordin.action_policy, "policy", ordin.action_policy)
    temporal_policy: Any = getattr(temporal, "policy", temporal)
    registry: Any = getattr(semantics, "registry", semantics)
    return _digest(
        {
            "ordin_version": __version__,
            "fail_on": ordin.policy.fail_on,
            "context": ordin.context.as_dict() if ordin.context is not None else None,
            "policy": action_policy.as_dict() if action_policy is not None else None,
            "temporal": temporal_policy.as_dict(),
            "semantics": registry.as_dict() if registry is not None else None,
        }
    )


class IntegrationSession:
    """One runtime/server session; no global state and no implicit persistence.

    Review and append are serialized. All proposals, including denials, count
    toward the temporal window; an observation is evidence only for a retained
    non-denied action. Snapshots are detached from live state.
    """

    def __init__(self, identity: SessionIdentity, gate: AgentGate) -> None:
        self.identity = identity
        self.gate = gate
        self.config_digest = configuration_digest(gate)
        self._actions: list[ActionEnvelope] = []
        self._observations: dict[str, ActionObservation] = {}
        self._denied: set[str] = set()
        self._sequence = 0
        self._closed = False
        self._lock = threading.RLock()
        self._runtime_active = False
        self._runtime_epoch = 0
        self._runtime_sources: dict[str, RuntimeEvidenceSource] = {}
        self._runtime_current: str | None = None
        self._runtime_history = RuntimeObservationHistory()
        self._runtime_bindings: dict[str, set[str]] = {}

    @property
    def runtime_session_digest(self) -> str:
        return _digest(
            {
                "identity": self.identity.key,
                "configuration": self.config_digest,
                "epoch": self._runtime_epoch,
            }
        )

    def bind_runtime_source(self, source: RuntimeEvidenceSource) -> None:
        """Explicitly enable host-owned runtime evidence before reviewing actions."""
        with self._lock:
            self.require_identity(self.identity)
            if (
                not isinstance(source, RuntimeEvidenceSource)
                or source.session_digest != self.runtime_session_digest
            ):
                raise RuntimeCorrelationError("runtime_observation_session_mismatch")
            if self._actions and not self._runtime_active:
                raise RuntimeCorrelationError("runtime_observation_unreviewed_history")
            if self._runtime_sources and any(
                s.sandbox_id != source.sandbox_id for s in self._runtime_sources.values()
            ):
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            proposed = {**self._runtime_sources, source.key: source}
            if len(proposed) > 128:
                raise ValueError("runtime source limit exceeded")
            packet = self._runtime_state()
            packet.update(
                sources=[s.as_dict() for _, s in sorted(proposed.items())],
                current_source=source.key,
            )
            validate_runtime("runtime_session", packet)
            self._runtime_sources = proposed
            self._runtime_current = source.key
            self._runtime_active = True

    def runtime_contract(self, action_id: str) -> RuntimeCapabilityContract:
        with self._lock:
            self.require_identity(self.identity)
            for contract in self._runtime_history.contracts:
                if contract.action_id == action_id:
                    return contract
            raise RuntimeCorrelationError("runtime_observation_action_mismatch")

    def bind_runtime_action_source(self, action_id: str, source: RuntimeEvidenceSource) -> None:
        """Host-authorized reporting scope update after an explicit policy change.

        This never grants or applies policy. The integration must validate/verify
        the policy and detect active drift. Accepted historical scopes remain.
        """
        with self._lock:
            contract = self.runtime_contract(action_id)
            old_sources, old_current = self._runtime_sources, self._runtime_current
            self.bind_runtime_source(source)
            proposed = {key: set(values) for key, values in self._runtime_bindings.items()}
            proposed.setdefault(contract.contract_id, set()).add(source.key)
            try:
                validate_runtime("runtime_session", self._runtime_state(bindings=proposed))
            except ValueError:
                self._runtime_sources, self._runtime_current = old_sources, old_current
                raise
            self._runtime_bindings = proposed

    def observe_runtime(self, observation: RuntimeObservation) -> None:
        with self._lock:
            self.require_identity(self.identity)
            if not self._runtime_active or not isinstance(observation, RuntimeObservation):
                raise RuntimeCorrelationError("runtime_observation_untrusted_source")
            contract = self.runtime_contract(observation.action_id)
            if observation.source_key not in self._runtime_bindings.get(
                contract.contract_id, set()
            ):
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            if observation.action_id in self._denied and observation.outcome != "denied":
                raise RuntimeCorrelationError("runtime_observation_denied_action")
            proposed = RuntimeObservationHistory(
                (*self._runtime_history.observations, observation), self._runtime_history.contracts
            )
            proposed.correlate(
                ActionHistory(tuple(self._actions)),
                session_digest=self.runtime_session_digest,
                allowed_sources=tuple(self._runtime_sources.values()),
            )
            validate_runtime("runtime_session", self._runtime_state(history=proposed))
            self._runtime_history = proposed

    def _runtime_state(
        self,
        *,
        history: RuntimeObservationHistory | None = None,
        bindings: dict[str, set[str]] | None = None,
        sequence: int | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "ordin.runtime_session.v1",
            "identity_key": self.identity.key,
            "configuration_digest": self.config_digest,
            "sequence": self._sequence if sequence is None else sequence,
            "epoch": self._runtime_epoch,
            "sources": [s.as_dict() for _, s in sorted(self._runtime_sources.items())],
            "current_source": self._runtime_current,
            "bindings": [
                {"contract_id": key, "source_keys": sorted(values)}
                for key, values in sorted(
                    (self._runtime_bindings if bindings is None else bindings).items()
                )
            ],
            "history": (self._runtime_history if history is None else history).as_dict(),
        }

    def runtime_snapshot(self) -> dict[str, Any] | None:
        """Separate secret-free sidecar; legacy snapshot/v1 remains unchanged."""
        with self._lock:
            self.require_identity(self.identity)
            if not self._runtime_active:
                return None
            result = self._runtime_state()
            validate_runtime("runtime_session", result)
            return result

    def snapshot_bundle(self) -> dict[str, Any]:
        """Explicit private persistence bundle: legacy state plus runtime sidecar.

        Legacy state still contains caller action parameters and has its existing
        privacy requirements. The runtime sidecar never adds those data.
        """
        with self._lock:
            return {"session": self.snapshot(), "runtime": self.runtime_snapshot()}

    def restore_runtime(
        self,
        payload: Mapping[str, Any],
        *,
        sources: Iterable[RuntimeEvidenceSource],
    ) -> None:
        """Restore only with host-owned source authorizations, never agent JSON."""
        with self._lock:
            validate_runtime("runtime_session", payload)
            if (
                payload["identity_key"] != self.identity.key
                or payload["configuration_digest"] != self.config_digest
            ):
                raise RuntimeCorrelationError("runtime_observation_session_mismatch")
            if payload["sequence"] != self._sequence:
                raise RuntimeCorrelationError("runtime_observation_session_mismatch")
            contexts = {s.key: s for s in sources}
            recorded = {_digest(s): s for s in payload["sources"]}
            # Source fields are ASCII identifiers/digests, so this agrees with
            # the runtime model's UTF-8 canonical source key.
            if not set(recorded).issubset(contexts) or any(
                contexts[k].as_dict() != s for k, s in recorded.items()
            ):
                raise RuntimeCorrelationError("runtime_observation_untrusted_source")
            epoch = payload["epoch"]
            expected = _digest(
                {"identity": self.identity.key, "configuration": self.config_digest, "epoch": epoch}
            )
            if any(s["session_digest"] != expected for s in recorded.values()):
                raise RuntimeCorrelationError("runtime_observation_session_mismatch")
            if len({s["sandbox_id"] for s in recorded.values()}) > 1:
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            retained = RuntimeObservationHistory.restore_trusted(
                payload["history"], sources=tuple(contexts.values())
            )
            retained.correlate(
                ActionHistory(tuple(self._actions)),
                session_digest=expected,
                allowed_sources=tuple(contexts.values()),
            )
            action_map = {a.action_id: a for a in self._actions}
            from ._runtime_json import digest as action_hash

            for contract in retained.contracts:
                action = action_map.get(contract.action_id)
                if action is None or action_hash(action.as_dict()) != contract.action_digest:
                    raise RuntimeCorrelationError("runtime_observation_action_mismatch")
            bindings = {b["contract_id"]: set(b["source_keys"]) for b in payload["bindings"]}
            if len(bindings) != len(payload["bindings"]) or set(bindings) != {
                c.contract_id for c in retained.contracts
            }:
                raise RuntimeCorrelationError("runtime_observation_contract_mismatch")
            if any(not values or not values.issubset(recorded) for values in bindings.values()):
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            if payload["current_source"] is not None and payload["current_source"] not in recorded:
                raise RuntimeCorrelationError("runtime_observation_source_mismatch")
            for observation in retained.observations:
                if observation.source_key not in bindings.get(observation.contract_id or "", set()):
                    raise RuntimeCorrelationError("runtime_observation_source_mismatch")
                if observation.action_id in self._denied and observation.outcome != "denied":
                    raise RuntimeCorrelationError("runtime_observation_denied_action")
            self._runtime_active = True
            self._runtime_epoch = epoch
            self._runtime_sources = {k: contexts[k] for k in recorded}
            self._runtime_current = payload["current_source"]
            self._runtime_history = retained
            self._runtime_bindings = bindings

    def require_identity(self, identity: SessionIdentity) -> None:
        if identity != self.identity:
            raise ValueError("integration session identity mismatch")
        if self._closed:
            raise ValueError("integration session has ended")

    def _would_evict(self, action_ids: Iterable[str]) -> bool:
        """Check retention without copying private action/observation snapshots."""
        with self._lock:
            if len(self._actions) < MAX_ACTION_HISTORY:
                return False
            oldest = self._actions[0].action_id
            return oldest is not None and oldest in action_ids

    def evaluate(
        self,
        action: ActionEnvelope,
        *,
        contract_check: MCPContractCheck | None = None,
        approval_supported: bool = True,
    ) -> AgentDecision:
        """Keep the core decision, recording denials from hosts without approval."""
        with self._lock:
            self.require_identity(self.identity)
            if not isinstance(approval_supported, bool):
                raise ValueError("approval_supported must be boolean")
            if not action.action_id:
                raise ValueError("session actions require an action_id")
            if any(prior.action_id == action.action_id for prior in self._actions):
                raise ValueError("duplicate session action_id; use a distinct ID for each proposal")
            # Validate the exact snapshot size before calling an audit sink or
            # changing state. Copying also prevents caller mutation after review.
            proposed = ActionEnvelope.from_dict(_load(_json(action.as_dict())))
            extra: dict[str, Any] = (
                {"contract_check": contract_check} if contract_check is not None else {}
            )
            if self._runtime_active:
                if self._runtime_current is None:
                    raise RuntimeCorrelationError("runtime_observation_untrusted_source")
                self._runtime_history.correlate(
                    ActionHistory(tuple(self._actions)),
                    session_digest=self.runtime_session_digest,
                    allowed_sources=tuple(self._runtime_sources.values()),
                )
                extra.update(
                    runtime_observations=self._runtime_history,
                    runtime_binding=RuntimeReviewBinding(
                        self.runtime_session_digest, self._sequence + 1, self._runtime_epoch
                    ),
                )
            decision = self.gate.evaluate_action(
                proposed,
                history=ActionHistory(tuple(self._actions)),
                observations=ObservationHistory(tuple(self._observations.values())),
                **extra,
            )
            if self._runtime_active:
                assert isinstance(decision.review, ActionReview)
                proposed = ActionEnvelope.from_dict(decision.review.action.as_dict())
            actions = (self._actions + [proposed])[-MAX_ACTION_HISTORY:]
            ids = {item.action_id for item in actions}
            observations = {key: value for key, value in self._observations.items() if key in ids}
            denied = self._denied.intersection(ids)
            if decision.denied or (decision.requires_approval and not approval_supported):
                denied.add(action.action_id)
            snapshot = self._snapshot(actions, observations, denied, self._sequence + 1)
            self._bounded(snapshot)
            if self._runtime_active:
                assert isinstance(decision.review, ActionReview)
                contract = derive_runtime_capability_contract(decision.review)
                contracts = tuple(
                    c for c in self._runtime_history.contracts if c.action_id in ids
                ) + (contract,)
                events = tuple(o for o in self._runtime_history.observations if o.action_id in ids)
                runtime_history = RuntimeObservationHistory(events, contracts)
                retained_contract_ids = {c.contract_id for c in contracts}
                bindings = {
                    key: set(values)
                    for key, values in self._runtime_bindings.items()
                    if key in retained_contract_ids
                }
                assert self._runtime_current is not None
                bindings[contract.contract_id] = {self._runtime_current}
                validate_runtime(
                    "runtime_session",
                    self._runtime_state(
                        history=runtime_history, bindings=bindings, sequence=self._sequence + 1
                    ),
                )
                self._runtime_history, self._runtime_bindings = runtime_history, bindings
            self._actions = actions[:-1] + [ActionEnvelope.from_dict(proposed.as_dict())]
            self._observations, self._denied = observations, denied
            self._sequence += 1
            return decision

    def observe(self, observation: ActionObservation) -> None:
        with self._lock:
            self.require_identity(self.identity)
            if not any(action.action_id == observation.action_id for action in self._actions):
                raise ValueError("observation does not match a retained session action")
            if observation.action_id in self._denied:
                raise ValueError("cannot attach execution evidence to a denied action")
            if observation.action_id in self._observations:
                raise ValueError("duplicate observation for session action")
            copied = ActionObservation.from_dict(_load(_json(observation.as_dict())))
            proposed = dict(self._observations)
            proposed[observation.action_id] = copied
            self._bounded(self._snapshot(self._actions, proposed, self._denied, self._sequence))
            self._observations = proposed

    def reset(self) -> None:
        with self._lock:
            self.require_identity(self.identity)
            self._actions.clear()
            self._observations.clear()
            self._denied.clear()
            if self._runtime_active:
                self._runtime_epoch += 1
                self._runtime_sources.clear()
                self._runtime_current = None
                self._runtime_history = RuntimeObservationHistory()
                self._runtime_bindings.clear()
            # Preserve monotonic sequence numbering across resets.

    def end(self) -> None:
        with self._lock:
            self.reset()
            self._closed = True

    def _snapshot(
        self,
        actions: list[ActionEnvelope],
        observations: dict[str, ActionObservation],
        denied: set[str],
        sequence: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": SESSION_SCHEMA_VERSION,
            "identity": self.identity.as_dict(),
            "configuration_digest": self.config_digest,
            "sequence": sequence,
            "history": ActionHistory(tuple(actions)).as_dict(),
            "observations": ObservationHistory(tuple(observations.values())).as_dict(),
            "denied_action_ids": sorted(denied),
        }

    @staticmethod
    def _bounded(payload: Mapping[str, Any]) -> None:
        if len(_json(payload).encode()) > MAX_SESSION_BYTES:
            raise ValueError("session state exceeds its byte limit")

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self.require_identity(self.identity)
            return self._snapshot(self._actions, self._observations, self._denied, self._sequence)

    @classmethod
    def restore(
        cls, identity: SessionIdentity, gate: AgentGate, payload: Mapping[str, Any]
    ) -> IntegrationSession:
        parsed = _load(_json(payload))
        if validate_named_schema("integration_session", parsed):
            raise ValueError("invalid integration session schema")
        session = cls(identity, gate)
        if parsed["identity"] != identity.as_dict():
            raise ValueError("stored session identity mismatch")
        if parsed["configuration_digest"] != session.config_digest:
            raise ValueError(
                "stored session policy/semantics/version mismatch; explicit reset required"
            )
        actions = ActionHistory.from_dict(parsed["history"])
        observations = ObservationHistory.from_dict(parsed["observations"])
        ids = [action.action_id for action in actions.actions]
        if None in ids or len(set(ids)) != len(ids):
            raise ValueError("stored session action IDs must be present and unique")
        denied = set(parsed["denied_action_ids"])
        if len(denied) != len(parsed["denied_action_ids"]) or not denied.issubset(ids):
            raise ValueError("invalid denied session action IDs")
        if any(
            item.action_id not in ids or item.action_id in denied
            for item in observations.observations
        ):
            raise ValueError("stored observation linkage mismatch")
        if parsed["sequence"] < len(ids):
            raise ValueError("invalid session sequence")
        session._actions = list(actions.actions)
        session._observations = observations.by_action_id()
        session._denied = denied
        session._sequence = parsed["sequence"]
        return session


class SqliteSessionStore:
    """Opt-in private storage for separate hook processes, with atomic updates.

    The containing directory must be trusted. This protects against accidental
    public file modes and concurrent lost updates, not an attacker with the
    owning user's access. Missing state never implicitly creates a session.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).absolute()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with private_database(self.path, "session") as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sessions (identity TEXT PRIMARY KEY, snapshot TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runtime_sessions (identity TEXT PRIMARY KEY, snapshot TEXT NOT NULL)"
            )
            yield connection

    @contextmanager
    def transaction(
        self,
        identity: SessionIdentity,
        gate: AgentGate,
        *,
        create: bool = False,
        reset: bool = False,
        runtime_sources: Iterable[RuntimeEvidenceSource] = (),
    ) -> Iterator[IntegrationSession]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT snapshot FROM sessions WHERE identity=?", (identity.key,)
            ).fetchone()
            if row is None:
                if not create:
                    raise ValueError("session state missing; run the session-start lifecycle hook")
                if (
                    connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                    >= MAX_SESSIONS
                ):
                    raise ValueError("session database is full; end an existing session")
            session = (
                IntegrationSession(identity, gate)
                if row is None or reset
                else IntegrationSession.restore(identity, gate, _load(row[0]))
            )
            runtime_row = connection.execute(
                "SELECT snapshot FROM runtime_sessions WHERE identity=?", (identity.key,)
            ).fetchone()
            if runtime_row is not None:
                runtime_state = _load(runtime_row[0])
                if reset:
                    validate_runtime("runtime_session", runtime_state)
                    session._runtime_active = True
                    session._runtime_epoch = runtime_state["epoch"] + 1
                    session._sequence = max(session._sequence, runtime_state["sequence"])
                else:
                    session.restore_runtime(runtime_state, sources=runtime_sources)
            yield session
            if session._closed:
                connection.execute("DELETE FROM sessions WHERE identity=?", (identity.key,))
                connection.execute("DELETE FROM runtime_sessions WHERE identity=?", (identity.key,))
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO sessions VALUES (?, ?)",
                    (identity.key, _json(session.snapshot())),
                )
                updated_runtime_state = session.runtime_snapshot()
                if updated_runtime_state is None:
                    connection.execute(
                        "DELETE FROM runtime_sessions WHERE identity=?", (identity.key,)
                    )
                else:
                    connection.execute(
                        "INSERT OR REPLACE INTO runtime_sessions VALUES (?, ?)",
                        (identity.key, _json(updated_runtime_state)),
                    )
