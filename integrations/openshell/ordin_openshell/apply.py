"""Explicit approved policy updates, with verification and effective-policy readback.

The only mutation is one named-sandbox policy set. This module has no action
execution, creation/start/delete, automatic retry, or rollback path. The host
owns approval and exclusive runtime management; CLI readback is not a remote CAS.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json, digest, freeze, thaw
from ordin.enforcement_backend import EnforcementPlan
from ordin.runtime_boundary import RuntimeCapabilityBoundary, verify_runtime_capability
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.runtime_requests import RuntimeRequestBoundary, verify_runtime_request_capability
from ordin.runtime_requests_v2 import (
    RuntimeRequestContractV2,
    RuntimeRequestBoundaryV2,
    verify_runtime_request_authority,
    verify_request_contract,
)
from .extension import has_tcp_literals, require_runtime_identity

from .backend_cli import OpenShellCLI, OpenShellCommandError, identifier
from .compiler import OpenShellBackend
from .model import policy_errors
from .prover import MODELED_DOMAINS, verify_with_openshell_prover


def canonical_runtime_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Account only for known, authority-neutral OpenShell serialization defaults."""
    data = thaw(freeze(value, max_depth=12))
    if not isinstance(data, dict):
        raise ValueError("openshell_policy_shape")
    if data.get("network_middlewares") == {}:
        data.pop("network_middlewares")
    data.setdefault("network_policies", {})
    fs = data.get("filesystem_policy")
    if isinstance(fs, dict):
        fs.setdefault("read_only", [])
        fs.setdefault("read_write", [])
    rules = data["network_policies"]
    if not isinstance(rules, dict):
        raise ValueError("openshell_policy_shape")
    for key, rule in rules.items():
        if not isinstance(rule, dict):
            raise ValueError("openshell_policy_shape")
        if rule.get("name") == key:
            rule.pop("name")
        endpoints = rule.get("endpoints", [])
        if not isinstance(endpoints, list):
            raise ValueError("openshell_policy_shape")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                raise ValueError("openshell_policy_shape")
            # Proto round trips omit these empty strings/vectors. Any nonempty
            # value stays present and the supported-subset validator rejects it.
            for name in ("path", "tls", "access"):
                if endpoint.get(name) == "":
                    endpoint.pop(name)
            for name in ("ports", "deny_rules"):
                if endpoint.get(name) == []:
                    endpoint.pop(name)
            for name in (
                "allow_encoded_slash",
                "websocket_credential_rewrite",
                "request_body_credential_rewrite",
                "allow_uninspected_credentials",
            ):
                if endpoint.get(name) is False:
                    endpoint.pop(name)
            if endpoint.get("protocol") == "mcp":
                entries = endpoint.get("rules", [])
                if not isinstance(entries, list):
                    raise ValueError("openshell_policy_shape")
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError("openshell_policy_shape")
                    allow = entry.get("allow", {})
                    if not isinstance(allow, dict):
                        raise ValueError("openshell_policy_shape")
                    if "tool" in allow and "params" not in allow:
                        allow["params"] = {"name": allow.pop("tool")}
                    params = allow.get("params", {})
                    if not isinstance(params, dict):
                        raise ValueError("openshell_policy_shape")
                    matcher = params.get("name")
                    if (
                        isinstance(matcher, dict)
                        and matcher.get("any") == []
                        and isinstance(matcher.get("glob"), str)
                    ):
                        matcher.pop("any")
                    if (
                        isinstance(matcher, dict)
                        and matcher.get("glob") == ""
                        and isinstance(matcher.get("any"), list)
                        and matcher["any"]
                    ):
                        matcher.pop("glob")
    if policy_errors(data):
        raise ValueError("openshell_policy_unsupported")
    return data


@dataclass(frozen=True)
class RuntimePolicySnapshot:
    sandbox: str
    sandbox_id: str
    created_at: str
    workspace: str
    version: int
    backend_hash: str
    config_revision: int
    policy: Mapping[str, Any]
    build_identity: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy", freeze(self.policy, max_depth=12))
        object.__setattr__(self, "build_identity", freeze(self.build_identity))

    @property
    def policy_digest(self) -> str:
        return digest(self.policy)

    @property
    def identity(self) -> dict[str, Any]:
        return {
            "sandbox_id": self.sandbox_id,
            "created_at": self.created_at,
            "workspace": self.workspace,
            "version": self.version,
            "backend_hash": self.backend_hash,
            "config_revision": self.config_revision,
            "policy_digest": self.policy_digest,
            **({"build_identity": thaw(self.build_identity)} if self.build_identity else {}),
        }


def _number(value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise OpenShellCommandError("openshell_policy_readback_invalid")
    return value


def _hash(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise OpenShellCommandError("openshell_policy_readback_invalid")
    return value


def read_runtime_policy(cli: OpenShellCLI, sandbox: str) -> RuntimePolicySnapshot:
    """Require effective configuration, loaded revision and admitted workload agreement."""
    identifier(sandbox)
    current = cli.json(("policy", "get", sandbox, "--full", "--output", "json"))
    if (
        current.get("sandbox") != sandbox
        or current.get("scope") != "sandbox"
        or current.get("status") != "effective"
        or current.get("policy_source") != "sandbox"
    ):
        raise OpenShellCommandError("openshell_policy_readback_scope")
    version = _number(current.get("version"))
    if _number(current.get("active_version")) != version:
        raise OpenShellCommandError("openshell_policy_not_loaded", uncertain=True)
    backend_hash = _hash(current.get("hash"))
    revision = _number(current.get("config_revision"))
    try:
        policy = canonical_runtime_policy(current["policy"])
    except (ValueError, TypeError, KeyError):
        raise OpenShellCommandError("openshell_policy_readback_unsupported") from None
    loaded = cli.json(
        ("policy", "get", sandbox, "--rev", str(version), "--full", "--output", "json")
    )
    if (
        loaded.get("sandbox") != sandbox
        or loaded.get("scope") != "sandbox"
        or loaded.get("status") != "loaded"
        or _number(loaded.get("version")) != version
        or _number(loaded.get("active_version")) != version
        or loaded.get("hash") != backend_hash
    ):
        raise OpenShellCommandError("openshell_policy_not_loaded", uncertain=True)
    try:
        if digest(canonical_runtime_policy(loaded["policy"])) != digest(policy):
            raise OpenShellCommandError("openshell_policy_drift", uncertain=True)
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, OpenShellCommandError):
            raise
        raise OpenShellCommandError("openshell_policy_readback_unsupported") from None
    detail = cli.json(("sandbox", "get", sandbox, "--output", "json"))
    admission = detail.get("configuration_admission")
    if (
        detail.get("name") != sandbox
        or detail.get("workspace") != cli.workspace
        or detail.get("phase") != "Ready"
        or detail.get("policy_source") != "sandbox"
        or _number(detail.get("current_policy_version")) != version
        or not isinstance(admission, dict)
        or admission.get("state") != "accepted"
        or _number(admission.get("policy_version")) != version
        or admission.get("policy_hash") != backend_hash
        or _number(admission.get("config_revision")) != revision
    ):
        raise OpenShellCommandError("openshell_policy_not_admitted", uncertain=True)
    sandbox_id, created_at = detail.get("id"), detail.get("created_at")
    if (
        not isinstance(sandbox_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}", sandbox_id)
        or not isinstance(created_at, str)
        or not created_at
        or len(created_at) > 128
    ):
        raise OpenShellCommandError("openshell_policy_readback_identity")
    try:
        if digest(canonical_runtime_policy(detail["policy"])) != digest(policy):
            raise OpenShellCommandError("openshell_policy_drift", uncertain=True)
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, OpenShellCommandError):
            raise
        raise OpenShellCommandError("openshell_policy_readback_unsupported") from None
    return RuntimePolicySnapshot(
        sandbox,
        sandbox_id,
        created_at,
        cli.workspace,
        version,
        backend_hash,
        revision,
        policy,
        {
            key: admission[key]
            for key in (
                "runtime_extension_id",
                "runtime_source_digest",
                "gateway_source_digest",
                "cli_source_digest",
                "confirmed_backend",
                "egress_interception",
                "request_attribution",
                "staged_tcp_confirmed",
            )
            if key in admission
        },
    )


@dataclass(frozen=True)
class PolicyApplyPreparation:
    status: str
    reason_code: str
    plan: EnforcementPlan = field(repr=False)
    sandbox: str
    current: RuntimePolicySnapshot | None = field(default=None, repr=False)
    verification: tuple[Mapping[str, Any], ...] = ()
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "verification", freeze(self.verification))
        object.__setattr__(self, "context", freeze(self.context))

    @property
    def request_id(self) -> str:
        return "pa:" + digest(
            {
                "plan_id": self.plan.plan_id,
                "sandbox": self.sandbox,
                "current": self.current.identity if self.current else None,
                "verification": thaw(self.verification),
                "context": thaw(self.context),
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "request_id": self.request_id,
            "action_digest": self.plan.contract.action_digest,
            "contract_id": self.plan.contract.contract_id,
            "contract_digest": self.plan.contract.digest,
            "plan_id": self.plan.plan_id,
            "policy_digest": self.plan.policy_digest,
            "policy_bytes_digest": hashlib.sha256(policy_bytes(self.plan)).hexdigest(),
            "sandbox_id_digest": digest(self.current.sandbox_id) if self.current else None,
            "current_policy_digest": self.current.policy_digest if self.current else None,
            "verification": thaw(self.verification),
        }


def policy_bytes(plan: EnforcementPlan) -> bytes:
    return (canonical_json(plan.policy) + "\n").encode("utf-8")


def prepare_openshell_apply(
    plan: EnforcementPlan,
    *,
    backend: OpenShellBackend,
    sandbox: str,
    cli: OpenShellCLI | None = None,
    capability_boundary: RuntimeCapabilityBoundary | None = None,
    backend_boundary_policy: Mapping[str, Any] | None = None,
    prover_executable: str = "openshell-prover",
    timeout: float = 30,
    request_boundary: RuntimeRequestBoundary | RuntimeRequestBoundaryV2 | None = None,
) -> PolicyApplyPreparation:
    """Read/validate/prove only. A successful preparation still requires host approval."""
    identifier(sandbox)
    cli = cli or OpenShellCLI()
    if not 1 < timeout <= 60:
        raise ValueError("openshell_apply_timeout_invalid")
    steps: list[Mapping[str, Any]] = []
    current = None
    context = {**cli.context, "prover_executable": prover_executable}

    def result(status, code):
        return PolicyApplyPreparation(status, code, plan, sandbox, current, tuple(steps), context)

    if (
        plan.mode != "enforce"
        or backend.mode != "enforce"
        or plan.contract.grant_state == "diagnostic"
    ):
        return result("unsupported", "openshell_apply_non_executable")
    validated = backend.validate(plan)
    steps.append({"step": "backend_validation", **validated.as_dict()})
    if not validated.ok or validated.policy_digest != plan.policy_digest:
        return result("unsupported", "openshell_apply_validation_failed")
    if any(n.protocol in {"mcp", "graphql", "json-rpc"} for n in plan.contract.network):
        if backend.request_contract is None or request_boundary is None:
            return result("unsupported", "runtime_request_boundary_required")
    if request_boundary is not None:
        if backend.request_contract is None:
            return result("unsupported", "runtime_request_contract_required")
        requests_verified = verify_request_contract(backend.request_contract, request_boundary)
        requests_report = requests_verified.as_dict()
        counter = requests_report.pop("counterexample")
        requests_report["counterexample_digest"] = digest(counter) if counter is not None else None
        steps.append({"step": "request_boundary", **requests_report})
        if not requests_verified.ok:
            return result(requests_verified.result, requests_verified.reason_code)
    if capability_boundary is not None:
        verified = (
            verify_runtime_request_authority(
                backend.request_contract,
                RuntimeRequestBoundaryV2(capability_boundary, backend.request_contract.requests),
            )
            if isinstance(backend.request_contract, RuntimeRequestContractV2)
            else verify_runtime_capability(plan.contract, capability_boundary)
        )
        report = verified.as_dict()
        counter = report.pop("counterexample")
        report["counterexample_digest"] = digest(counter) if counter is not None else None
        steps.append({"step": "capability_boundary", **report})
        if not verified.ok:
            return result(verified.result, verified.reason_code)
    if backend_boundary_policy is not None:
        try:
            boundary_bytes = (
                canonical_json(freeze(backend_boundary_policy, max_depth=12)) + "\n"
            ).encode()
            if len(boundary_bytes) > MAX_RUNTIME_BYTES:
                raise ValueError("openshell_boundary_size")
            with tempfile.TemporaryDirectory(prefix="ordin-apply-proof-") as directory:
                candidate, boundary = (
                    Path(directory) / "candidate.json",
                    Path(directory) / "boundary.json",
                )
                candidate.write_bytes(policy_bytes(plan))
                boundary.write_bytes(boundary_bytes)
                candidate.chmod(0o600)
                boundary.chmod(0o600)
                domains = MODELED_DOMAINS | (
                    {"credentials"} if plan.contract.credentials else set()
                )
                verified_backend = verify_with_openshell_prover(
                    candidate,
                    boundary,
                    executable=prover_executable,
                    timeout=min(timeout, 15),
                    required_domains=frozenset(domains),
                )
            # Keep coverage and hashes, without logging raw counterexample targets.
            report = verified_backend.as_dict()
            counter = report.pop("counterexample")
            report["counterexample_digest"] = digest(counter) if counter is not None else None
            steps.append({"step": "openshell_prover", **report})
            if not verified_backend.ok:
                return result(verified_backend.result, verified_backend.reason_code)
            if (
                verified_backend.candidate_digest != hashlib.sha256(policy_bytes(plan)).hexdigest()
                or verified_backend.boundary_digest != hashlib.sha256(boundary_bytes).hexdigest()
            ):
                return result("unsupported", "openshell_prover_input_binding_mismatch")
        except (ValueError, OSError, TypeError):
            return result("unsupported", "openshell_apply_boundary_input_invalid")
    try:
        cli.require_compatible()
        current = read_runtime_policy(cli, sandbox)
        if plan.metadata.get("runtime_extension"):
            try:
                require_runtime_identity(
                    current.build_identity, require_staged_tcp=has_tcp_literals(plan.contract)
                )
            except ValueError as exc:
                return result("unsupported", str(exc))
        # Running startup controls cannot be changed by a live network update.
        for section in ("filesystem_policy", "landlock", "process"):
            if current.policy[section] != plan.policy[section]:
                return result("unsupported", "openshell_apply_startup_policy_mismatch")
    except OpenShellCommandError as exc:
        return result("inconclusive" if exc.uncertain else "unsupported", exc.reason_code)
    return result("requires_approval", "openshell_apply_requires_approval")


@dataclass(frozen=True)
class PolicyApplyResult:
    status: str
    reason_code: str
    preparation: PolicyApplyPreparation
    mutation_attempted: bool = False
    current: RuntimePolicySnapshot | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "preparation": self.preparation.as_dict(),
            "mutation_attempted": self.mutation_attempted,
            "active_policy_digest": self.current.policy_digest if self.current else None,
        }

    def evidence_source(self, session_digest: str) -> RuntimeEvidenceSource:
        if self.status != "applied" or self.current is None:
            raise ValueError("openshell_apply_not_verified")
        return RuntimeEvidenceSource(
            "openshell", session_digest, self.current.sandbox_id, self.current.policy_digest
        )


def apply_openshell_policy(
    plan: EnforcementPlan,
    *,
    backend: OpenShellBackend,
    sandbox: str,
    approval_request_id: str | None = None,
    cli: OpenShellCLI | None = None,
    capability_boundary: RuntimeCapabilityBoundary | None = None,
    backend_boundary_policy: Mapping[str, Any] | None = None,
    prover_executable: str = "openshell-prover",
    timeout: float = 30,
    audit: Any = None,
    request_boundary: RuntimeRequestBoundary | RuntimeRequestBoundaryV2 | None = None,
) -> PolicyApplyResult:
    """Explicit host operation: re-prepare, check exact approval, set once, read back.

    The host must protect approval input; do not expose this operator entrypoint
    or its audit files as an agent tool. No preparation JSON is trusted as proof.
    """
    cli = cli or OpenShellCLI()
    prepared = prepare_openshell_apply(
        plan,
        backend=backend,
        sandbox=sandbox,
        cli=cli,
        capability_boundary=capability_boundary,
        backend_boundary_policy=backend_boundary_policy,
        prover_executable=prover_executable,
        timeout=timeout,
        request_boundary=request_boundary,
    )
    if prepared.status != "requires_approval":
        return PolicyApplyResult(prepared.status, prepared.reason_code, prepared)
    if approval_request_id != prepared.request_id:
        return PolicyApplyResult("requires_approval", "openshell_apply_requires_approval", prepared)
    assert prepared.current is not None
    attempted = False
    active = None
    try:
        # A final read before mutation catches changes during proof/approval.
        before = read_runtime_policy(cli, sandbox)
        if plan.metadata.get("runtime_extension"):
            require_runtime_identity(
                before.build_identity, require_staged_tcp=has_tcp_literals(plan.contract)
            )
        if before.identity != prepared.current.identity:
            return PolicyApplyResult("inconclusive", "openshell_policy_drift", prepared)
        if audit is not None:
            audit.record(prepared, "attempted")  # A failed durable pre-record prevents mutation.
        if before.policy_digest != plan.policy_digest:
            with tempfile.TemporaryDirectory(prefix="ordin-policy-apply-") as directory:
                candidate = Path(directory) / "candidate.json"
                candidate.write_bytes(policy_bytes(plan))
                candidate.chmod(0o600)
                attempted = True
                cli.run(
                    (
                        "policy",
                        "set",
                        sandbox,
                        "--policy",
                        str(candidate),
                        "--wait",
                        "--timeout",
                        str(max(1, int(timeout) - 1)),
                    ),
                    timeout=timeout,
                )
        active = read_runtime_policy(cli, sandbox)
        if plan.metadata.get("runtime_extension"):
            require_runtime_identity(
                active.build_identity, require_staged_tcp=has_tcp_literals(plan.contract)
            )
        if (
            active.sandbox_id != before.sandbox_id
            or active.created_at != before.created_at
            or active.policy_digest != plan.policy_digest
        ):
            outcome = PolicyApplyResult(
                "inconclusive", "openshell_policy_drift", prepared, attempted
            )
        else:
            outcome = PolicyApplyResult(
                "applied", "openshell_policy_applied", prepared, attempted, active
            )
        if audit is not None:
            audit.record(prepared, outcome.status, result=outcome)
        return outcome
    except OpenShellCommandError as exc:
        outcome = PolicyApplyResult(
            "inconclusive" if attempted else "unsupported", exc.reason_code, prepared, attempted
        )
        if audit is not None:
            try:
                audit.record(prepared, outcome.status, result=outcome)
            except (ValueError, OSError):
                pass  # The returned digest-bound result still exposes the uncertain attempt.
        return outcome
    except (ValueError, OSError, TypeError):
        outcome = PolicyApplyResult(
            "inconclusive" if attempted else "unsupported",
            "openshell_apply_io_or_audit_failed",
            prepared,
            attempted,
        )
        if audit is not None:
            try:
                audit.record(prepared, outcome.status, result=outcome)
            except (ValueError, OSError, TypeError):
                pass
        return outcome
