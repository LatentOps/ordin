"""Explicit asynchronous TypeSafe 0.2.0 API contract; no default network calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import ssl
import threading
import time
from typing import Any
from dataclasses import dataclass, field
from pathlib import Path

from ordin import ActionEnvelope
from ordin._runtime_json import digest as core_digest
from ordin.assurance import (
    ApprovedSecurityProfile,
    HostApproval,
    HostConstraintAssessment,
    HostEvidenceSource,
)
from ordin.assurance._files import read_scoped_file
from ordin.assurance._json import canonical_json, digest, freeze, validate
from ordin.assurance.codex_security._validation import loads
from ordin.assurance.models import ModelAnswer

from .protocol import ProviderDescriptor, SanitizedDecisionState, SecurityQuestionSet, evidence

HOST = "api.typesafe.ai"


@dataclass(frozen=True)
class TypeSafeConfiguration:
    """Operator pins TLS trust outside the target; environment proxies are unused."""

    ca_bundle: Path
    ca_sha256: str
    max_requests: int = 1
    max_cost_usd: float = 1
    max_input_tokens: int = 8192
    max_request_bytes: int = 16384
    max_response_bytes: int = 65536

    def __post_init__(self):
        if not isinstance(self.ca_bundle, Path) or not self.ca_bundle.is_absolute():
            raise ValueError("hosted TLS trust requires a host-selected absolute CA file")
        validate(
            "assurance_authority_ref", {"authority_id": "tls", "boundary_digest": self.ca_sha256}
        )
        if (
            type(self.max_requests) is not int
            or not 1 <= self.max_requests <= 32
            or type(self.max_input_tokens) is not int
            or not 1 <= self.max_input_tokens <= 65536
            or (
                isinstance(self.max_cost_usd, bool)
                or not isinstance(self.max_cost_usd, (int, float))
                or not math.isfinite(self.max_cost_usd)
                or not 0 < self.max_cost_usd <= 100
            )
        ):
            raise ValueError("hosted request/token/spend budgets invalid")
        if (
            type(self.max_request_bytes) is not int
            or not 1024 <= self.max_request_bytes <= 16384
            or type(self.max_response_bytes) is not int
            or not 1024 <= self.max_response_bytes <= 65536
        ):
            raise ValueError("hosted byte budgets invalid")

    @property
    def digest(self):
        return digest(
            "typesafe_configuration",
            {
                "host": HOST,
                "port": 443,
                "schema": "0.2.0",
                "ca_path_digest": core_digest(str(self.ca_bundle)),
                "ca_sha256": self.ca_sha256,
                "requests": self.max_requests,
                "cost_usd": self.max_cost_usd,
                "input_tokens": self.max_input_tokens,
                "request_bytes": self.max_request_bytes,
                "response_bytes": self.max_response_bytes,
            },
        )


def disclosure_action(
    config: TypeSafeConfiguration,
    *,
    state: SanitizedDecisionState | None = None,
    questions: SecurityQuestionSet | None = None,
    requested_model: str | None = None,
    expected_model_version: str | None = None,
) -> ActionEnvelope:
    discovery = state is None
    if discovery and any(
        v is not None for v in (questions, requested_model, expected_model_version)
    ):
        raise ValueError("discovery does not send semantic content")
    if not discovery and (
        not isinstance(state, SanitizedDecisionState)
        or not isinstance(questions, SecurityQuestionSet)
        or not requested_model
        or not expected_model_version
    ):
        raise ValueError("hosted inference requires exact state/question/model disclosure")
    if state is not None and not state.remote_eligible:
        raise ValueError("private/unredactable semantic content cannot use hosted inference")
    return ActionEnvelope(
        "decision_model",
        "discover_models" if discovery else "inference",
        {
            "provider": "typesafe",
            "destination": "https://api.typesafe.ai:443",
            "configuration_digest": config.digest,
            "input_digest": state.digest if state else None,
            "host_source_key": state.host_source_key if state else None,
            "question_set_digest": questions.digest if questions else None,
            "requested_model": requested_model,
            "expected_model_version": expected_model_version,
            "max_requests": config.max_requests,
            "max_cost_usd": config.max_cost_usd,
            "disclosure": "Selected sanitized task/action content is sent to TypeSafe; model discovery sends credentials and metadata only.",
        },
    )


@dataclass(frozen=True)
class _DisclosureSeal:
    digest: str


@dataclass(frozen=True)
class HostedDisclosure:
    """Scoped primitive receipt; the provider receives no host issuance object."""

    request_digest: str
    source_key: str
    profile_digest: str
    consent_ref: str
    configuration_digest: str
    expires_at: float
    max_requests: int
    _seal: _DisclosureSeal | None = field(default=None, repr=False, compare=False)
    _lock: Any = field(default_factory=threading.Lock, repr=False, compare=False)
    _used: list[int] = field(default_factory=lambda: [0], repr=False, compare=False)

    def material(self):
        return {
            "request": self.request_digest,
            "source": self.source_key,
            "profile": self.profile_digest,
            "consent": self.consent_ref,
            "configuration": self.configuration_digest,
            "expires": self.expires_at,
            "max_requests": self.max_requests,
        }

    def __post_init__(self):
        if not isinstance(self._seal, _DisclosureSeal) or self._seal.digest != digest(
            "hosted_disclosure", self.material()
        ):
            raise ValueError(
                "hosted disclosure requires protected actual approval/isolation/spend review"
            )

    def consume(self, request, config):
        with self._lock:
            if (
                self.configuration_digest != config.digest
                or self.request_digest != core_digest(request.as_dict())
                or time.monotonic() >= self.expires_at
                or self._used[0] >= self.max_requests
            ):
                return False
            self._used[0] += 1
            return True


def authorize_hosted_disclosure(
    source: HostEvidenceSource,
    profile: ApprovedSecurityProfile,
    approval: HostApproval,
    scope_assessment: HostConstraintAssessment,
    config: TypeSafeConfiguration,
    request: ActionEnvelope,
    *,
    lifetime_seconds=60,
) -> HostedDisclosure:
    """Host calls after actual consent and verified egress/credential/spend controls.

    API v0.2.0 has no per-request currency cap. The authenticated host assessment
    must establish the provider-account/gateway spend ceiling separately; this
    SDK cannot infer billing enforcement from token counts or a price estimate.
    """
    if not isinstance(source, HostEvidenceSource) or not isinstance(
        profile, ApprovedSecurityProfile
    ):
        raise ValueError("hosted disclosure requires protected host/profile selection")
    source._check_profile(profile)
    target = core_digest(request.as_dict())
    if (
        request.kind != "decision_model"
        or request.operation not in {"inference", "discover_models"}
        or request.parameters.get("configuration_digest") != config.digest
    ):
        raise ValueError(
            "hosted disclosure request does not match selected destination/configuration"
        )
    if request.operation == "inference" and request.parameters.get("host_source_key") != source.key:
        raise ValueError("hosted disclosure belongs to another protected task/source scope")
    for value, model in ((approval, HostApproval), (scope_assessment, HostConstraintAssessment)):
        if (
            not isinstance(value, model)
            or value.source_key != source.key
            or value.profile_digest != profile.digest
            or value.action_digest != target
        ):
            raise ValueError("hosted consent/scope is stale or belongs to another disclosure")
    if (
        scope_assessment.kind != "semantic_hosted_scope"
        or scope_assessment.invariant_id != "semantic.hosted_scope"
        or scope_assessment.status != "satisfied"
    ):
        raise ValueError("hosted egress/credential/spend isolation is unresolved")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
        raise ValueError("hosted consent lifetime must be bounded")
    values = dict(
        request_digest=target,
        source_key=source.key,
        profile_digest=profile.digest,
        consent_ref=approval.receipt_id,
        configuration_digest=config.digest,
        expires_at=time.monotonic() + lifetime_seconds,
        max_requests=config.max_requests,
    )
    preview = object.__new__(HostedDisclosure)
    for key, value in values.items():
        object.__setattr__(preview, key, value)
    return HostedDisclosure(
        **values, _seal=_DisclosureSeal(digest("hosted_disclosure", preview.material()))
    )


class AsyncHTTPS:
    """Fixed HTTPS host, pinned CA, no proxy/redirect/retry, bounded full deadline."""

    def __init__(self, config):
        self.config = config

    async def request_json(self, method, path, *, api_key, body, deadline_ms):
        _deadline(deadline_ms)
        api_key = _api_key(api_key)
        if method not in {"GET", "POST"} or (method, path) not in {
            ("GET", "/v1/models"),
            ("POST", "/v1/systemone"),
        }:
            raise ValueError("unsupported provider endpoint")
        raw = b"" if body is None else canonical_json(body).encode()
        if len(raw) > self.config.max_request_bytes:
            raise ValueError("provider request byte budget exceeded")
        ca = read_scoped_file(self.config.ca_bundle.parent, self.config.ca_bundle.name)
        if hashlib.sha256(ca).hexdigest() != self.config.ca_sha256:
            raise ValueError("hosted TLS configuration changed")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=ca.decode("ascii"))
        writer = None

        async def request():
            nonlocal writer
            reader, writer = await asyncio.open_connection(
                HOST, 443, ssl=context, server_hostname=HOST, limit=8192
            )
            headers = (
                f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {api_key}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {len(raw)}\r\n\r\n"
            ).encode("ascii")
            writer.write(headers + raw)
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            if len(head) > 8192:
                raise ValueError("provider header byte budget exceeded")
            lines = head[:-4].decode("ascii").split("\r\n")
            parts = lines[0].split(" ", 2)
            if (
                len(parts) < 2
                or parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
                or not re.fullmatch(r"[0-9]{3}", parts[1])
            ):
                raise ValueError("provider HTTP status malformed")
            status = int(parts[1])
            values = {}
            for line in lines[1:]:
                key, separator, value = line.partition(":")
                if not separator or key.lower() in values:
                    raise ValueError("provider HTTP header malformed")
                values[key.lower()] = value.strip()
            if status != 200:
                # Error bodies can echo source or credentials; never parse/log them.
                return status, None
            if (
                values.get("content-type", "").split(";", 1)[0] != "application/json"
                or "transfer-encoding" in values
                or values.get("content-encoding", "identity") != "identity"
            ):
                raise ValueError("unsupported provider response framing")
            length = values.get("content-length")
            if length is not None:
                if (
                    not re.fullmatch(r"[0-9]{1,8}", length)
                    or int(length) > self.config.max_response_bytes
                ):
                    raise ValueError("provider response byte budget exceeded")
                data = await reader.readexactly(int(length))
            else:
                chunks = bytearray()
                while len(chunks) <= self.config.max_response_bytes:
                    chunk = await reader.read(
                        min(8192, self.config.max_response_bytes + 1 - len(chunks))
                    )
                    if not chunk:
                        break
                    chunks.extend(chunk)
                if len(chunks) > self.config.max_response_bytes:
                    raise ValueError("provider response byte budget exceeded")
                data = bytes(chunks)
            return status, loads(data)

        try:
            return await asyncio.wait_for(request(), deadline_ms / 1000)
        finally:
            if writer is not None:
                writer.close()
                # Do not await an unbounded peer-controlled TLS shutdown.


def _api_key(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 4096
        or not re.fullmatch(r"[!-~]+", value)
    ):
        raise ValueError("hosted credential absent or unsafe")
    return value


def _deadline(value):
    if type(value) is not int or not 1 <= value <= 30000:
        raise ValueError("provider deadline must be a bounded integer")


@dataclass(frozen=True)
class _CatalogSeal:
    digest: str


@dataclass(frozen=True)
class ModelCatalog:
    names: tuple[str, ...]
    catalog_digest: str
    _seal: _CatalogSeal = field(repr=False)

    def __post_init__(self):
        if not isinstance(self._seal, _CatalogSeal) or self._seal.digest != digest(
            "typesafe_catalog", [self.names, self.catalog_digest]
        ):
            raise ValueError("model catalog must come from validated explicit discovery")


async def discover_models(
    config: TypeSafeConfiguration,
    disclosure: HostedDisclosure,
    *,
    api_key,
    deadline_ms=250,
    transport=None,
) -> ModelCatalog:
    _deadline(deadline_ms)
    request = disclosure_action(config)
    if not isinstance(disclosure, HostedDisclosure) or not disclosure.consume(request, config):
        raise ValueError("model discovery lacks current explicit consent/scope")
    key = _api_key(api_key)
    status, packet = await asyncio.wait_for(
        (transport or AsyncHTTPS(config)).request_json(
            "GET", "/v1/models", api_key=key, body=None, deadline_ms=deadline_ms
        ),
        deadline_ms / 1000,
    )
    if (
        status != 200
        or not isinstance(packet, dict)
        or set(packet) != {"models"}
        or not isinstance(packet["models"], list)
        or not 1 <= len(packet["models"]) <= 128
    ):
        raise ValueError("provider model discovery refused or malformed")
    names = []
    for item in packet["models"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "description", "release_date"}
            or not isinstance(item["name"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", item["name"])
            or not isinstance(item["description"], str)
            or len(item["description"]) > 2048
            or not isinstance(item["release_date"], str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", item["release_date"])
        ):
            raise ValueError("provider catalog schema/version unsupported")
        names.append(item["name"])
    if len(set(names)) != len(names):
        raise ValueError("provider catalog has duplicate model names")
    selected_names = tuple(names)
    fingerprint = hashlib.sha256(
        json.dumps(
            packet, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
    ).hexdigest()
    return ModelCatalog(
        selected_names,
        fingerprint,
        _CatalogSeal(digest("typesafe_catalog", [selected_names, fingerprint])),
    )


class TypeSafeDecisionModel:
    """Async only. Fixed named noul questions never send generated instructions."""

    def __init__(
        self,
        config: TypeSafeConfiguration,
        catalog: ModelCatalog,
        *,
        requested_model: str,
        expected_model_version: str,
        disclosure: HostedDisclosure,
        api_key,
        transport=None,
    ):
        if (
            not isinstance(config, TypeSafeConfiguration)
            or not isinstance(catalog, ModelCatalog)
            or requested_model not in catalog.names
            or not expected_model_version
        ):
            raise ValueError(
                "select a model from actual discovery and pin its expected response version"
            )
        self._key = _api_key(api_key)
        self._config, self._requested = config, requested_model
        self._disclosure = disclosure
        self._transport = transport or AsyncHTTPS(config)
        self._descriptor = ProviderDescriptor(
            "typesafe",
            expected_model_version,
            "hosted",
            digest(
                "typesafe_model",
                [config.digest, catalog.catalog_digest, requested_model, expected_model_version],
            ),
        )
        self._metrics = {"calls": 0, "input_tokens": 0, "output_tokens": 0}

    @property
    def descriptor(self):
        return self._descriptor

    @property
    def metrics(self):
        return dict(self._metrics)

    async def evaluate_async(
        self, state: SanitizedDecisionState, questions: SecurityQuestionSet, *, deadline_ms: int
    ):
        _deadline(deadline_ms)
        started = time.monotonic()
        error = "none"
        answers: tuple[ModelAnswer, ...] = ()
        if not state.remote_eligible:
            return evidence(self.descriptor, state, questions, error_class="privacy")
        request = disclosure_action(
            self._config,
            state=state,
            questions=questions,
            requested_model=self._requested,
            expected_model_version=self.descriptor.model_version,
        )
        if not isinstance(self._disclosure, HostedDisclosure) or not self._disclosure.consume(
            request, self._config
        ):
            return evidence(self.descriptor, state, questions, error_class="refused")
        body = {
            "state": state.as_dict(),
            "model": self._requested,
            "questions": questions.provider_questions(),
        }
        if len(canonical_json(body).encode()) > self._config.max_request_bytes:
            return evidence(self.descriptor, state, questions, error_class="budget")
        try:
            self._metrics["calls"] += 1
            status, packet = await asyncio.wait_for(
                self._transport.request_json(
                    "POST", "/v1/systemone", api_key=self._key, body=body, deadline_ms=deadline_ms
                ),
                deadline_ms / 1000,
            )
            if status != 200:
                error = "refused" if status in {401, 403, 422, 429} else "transport"
            elif not isinstance(packet, dict) or set(packet) != {"model", "answers", "usage"}:
                error = "malformed"
            elif packet["model"] != self.descriptor.model_version:
                error = "version_mismatch"
            elif not isinstance(packet["answers"], dict) or set(packet["answers"]) != set(
                questions.question_ids
            ):
                error = "question_mismatch"
            else:
                parsed = []
                for identifier in questions.question_ids:
                    value = packet["answers"][identifier]
                    if (
                        not isinstance(value, dict)
                        or set(value) != {"type", "noul"}
                        or value["type"] != "noul"
                        or type(value["noul"]) not in {float, int}
                        or not math.isfinite(value["noul"])
                        or not 0 <= value["noul"] <= 1
                    ):
                        raise ValueError("provider typed answer malformed")
                    parsed.append(ModelAnswer(identifier, float(value["noul"])))
                usage = packet["usage"]
                if (
                    not isinstance(usage, dict)
                    or set(usage) != {"input_tokens", "output_tokens"}
                    or any(type(v) is not int or not 0 <= v <= 1_000_000 for v in usage.values())
                ):
                    raise ValueError("provider usage malformed")
                self._metrics["input_tokens"] += usage["input_tokens"]
                self._metrics["output_tokens"] += usage["output_tokens"]
                if self._metrics["input_tokens"] > self._config.max_input_tokens:
                    error = "budget"
                else:
                    answers = tuple(parsed)
        except asyncio.TimeoutError:
            error = "timeout"
        except asyncio.CancelledError:
            raise
        except ValueError:
            error = "malformed"
        except Exception:
            error = "transport"
        return evidence(
            self.descriptor,
            state,
            questions,
            answers=answers,
            error_class=error,
            latency_ms=round((time.monotonic() - started) * 1000, 6),
            consent_ref=self._disclosure.consent_ref,
        )
