"""Deterministic, no-widening compiler for the supported OpenShell 0.1.2 subset."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ordin._runtime_json import MAX_RUNTIME_ITEMS, digest, thaw
from ordin.enforcement_backend import BackendValidationResult, CompilationResult, EnforcementPlan
from ordin.runtime_contract import RuntimeCapabilityContract, _safe_path
from ordin.runtime_requests import RuntimeRequestContract, request_contract_errors

from .model import (
    PUBLIC_IPV4_RANGES,
    READ_METHODS,
    HTTP_METHODS,
    MAX_PROCESS_IDENTITY,
    exact_host,
    exact_request_path,
    policy_errors,
)

OpenShellCompilationResult = CompilationResult


def compile_openshell_policy(
    contract: RuntimeCapabilityContract,
    *,
    base_policy: Mapping[str, Any] | None = None,
    process_identity: tuple[int, int] | None = None,
    resource_kinds: Mapping[str, str] | None = None,
    credential_providers: Mapping[str, Mapping[str, Any]] | None = None,
    mode: str = "enforce",
    request_contract: RuntimeRequestContract | None = None,
) -> CompilationResult:
    if not isinstance(contract, RuntimeCapabilityContract):
        raise ValueError("compiler requires a runtime capability contract")
    if mode not in {"shadow", "enforce"}:
        raise ValueError("compiler mode must be shadow or enforce")
    unsupported = set()
    if contract.decision == "block":
        unsupported.add("decision.block")
    unsupported.update(f"unknowns.{u.domain}.{u.reason_code}" for u in contract.unknowns)
    if contract.privilege.escalation is not False:
        unsupported.add("privilege.escalation")
    if (
        process_identity is None
        or not isinstance(process_identity, (tuple, list))
        or len(process_identity) != 2
        or any(type(v) is not int or not 1 <= v <= MAX_PROCESS_IDENTITY for v in process_identity)
    ):
        unsupported.add("process.identity")
    elif (
        contract.privilege.required_euid is not None
        and process_identity[0] != contract.privilege.required_euid
    ):
        unsupported.add("privilege.required_euid")
    if contract.process.execution is None or (
        contract.process.execution and contract.process.spawn_children is not True
    ):
        unsupported.add("process.spawn_children")
    if request_contract is not None and (
        not isinstance(request_contract, RuntimeRequestContract)
        or request_contract.capability != contract
    ):
        return CompilationResult(
            "unsupported",
            "openshell",
            "runtime_request_contract_mismatch",
            unsupported_fields=("requests.contract",),
        )
    if request_contract is not None:
        unsupported.update(request_contract_errors(request_contract))
        if contract.credentials and any(n.protocol in {"mcp", "graphql"} for n in contract.network):
            unsupported.add("credentials.request_protocol_unrepresentable")
    if contract.tools and request_contract is None:
        unsupported.add("tools.request_identity")
    if resource_kinds is not None and (
        not isinstance(resource_kinds, Mapping)
        or len(resource_kinds) > MAX_RUNTIME_ITEMS
        or any(
            not isinstance(k, str)
            or not _safe_path(k)
            or not isinstance(v, str)
            or v not in {"file", "directory"}
            for k, v in resource_kinds.items()
        )
    ):
        # Operator configuration is still schema-bound. Never copy arbitrary
        # metadata (including accidentally supplied secrets) into a plan.
        return CompilationResult(
            "unsupported",
            "openshell",
            "openshell_operator_configuration_invalid",
            unsupported_fields=("config.resource_kinds",),
        )
    if credential_providers is not None:
        if (
            not isinstance(credential_providers, Mapping)
            or len(credential_providers) > MAX_RUNTIME_ITEMS
        ):
            return CompilationResult(
                "unsupported",
                "openshell",
                "credential_binding_unknown",
                unsupported_fields=("config.credential_providers",),
            )
        for configured_provider in credential_providers.values():
            if (
                not isinstance(configured_provider, Mapping)
                or set(configured_provider) != {"provider", "host", "port", "methods", "paths"}
                or not isinstance(configured_provider.get("provider"), str)
                or not configured_provider["provider"]
                or not exact_host(configured_provider.get("host"))
                or type(configured_provider.get("port")) is not int
                or not 1 <= configured_provider["port"] <= 65535
                or not isinstance(configured_provider.get("methods"), (list, tuple))
                or not 1 <= len(configured_provider["methods"]) <= 32
                or any(
                    not isinstance(m, str) or m not in HTTP_METHODS
                    for m in configured_provider["methods"]
                )
                or not isinstance(configured_provider.get("paths"), (list, tuple))
                or not 1 <= len(configured_provider["paths"]) <= MAX_RUNTIME_ITEMS
                or any(not exact_request_path(p) for p in configured_provider["paths"])
            ):
                return CompilationResult(
                    "unsupported",
                    "openshell",
                    "credential_binding_unknown",
                    unsupported_fields=("config.credential_providers",),
                )
    paths: dict[tuple[str, str], set[str]] = {}
    for filesystem_capability in contract.filesystem:
        if (
            filesystem_capability.path is None
            or not _safe_path(filesystem_capability.path)
            or filesystem_capability.scope == "unknown"
        ):
            unsupported.add("filesystem.scope")
            continue
        if (
            filesystem_capability.scope == "exact"
            and (resource_kinds or {}).get(filesystem_capability.path) != "file"
        ):
            unsupported.add("filesystem.exact_object_type")
        paths.setdefault((filesystem_capability.path, filesystem_capability.scope), set()).add(
            filesystem_capability.access
        )
    ro, rw = [], []
    for (path, scope), access in sorted(paths.items()):
        # Landlock read grants execution as well; write grants all path rights.
        # A less expressive backend must not silently broaden semantic rights.
        if {"read", "execute"}.issubset(access) and access.issubset(
            {"read", "execute", "metadata"}
        ):
            ro.append(path)
        elif {"read", "write", "delete", "execute"}.issubset(access):
            rw.append(path)
        else:
            unsupported.add("filesystem.primitive_would_widen")
    if not paths:
        unsupported.add("filesystem.empty_disables_isolation")
    executables = tuple(sorted(set(contract.process.executables)))
    if contract.process.execution and (
        not executables or any(not _safe_path(p) for p in executables)
    ):
        unsupported.add("process.executable_identity")
    if contract.network and (not executables or any(not _safe_path(p) for p in executables)):
        unsupported.add("network.binary_identity")
    rules: dict[str, Any] = {}
    for index, capability in enumerate(contract.network):
        if capability.protocol in {"graphql", "mcp"} and request_contract is not None:
            selected = [
                r
                for r in request_contract.requests
                if r.protocol == capability.protocol
                and r.host == capability.host
                and r.port == capability.port
                and capability.paths == (r.path,)
            ]
            if (
                not selected
                or not exact_host(capability.host)
                or type(capability.port) is not int
                or capability.methods != ("POST",)
                or capability.access not in {"read", "write"}
            ):
                unsupported.add("network.request_scope")
                continue
            protocol_endpoint: dict[str, Any] = {
                "host": capability.host,
                "port": capability.port,
                "path": capability.paths[0],
                "protocol": capability.protocol,
                "enforcement": "enforce",
                "allowed_ips": list(PUBLIC_IPV4_RANGES),
                "rules": [],
            }
            if capability.protocol == "graphql":
                protocol_endpoint["rules"] = [
                    {
                        "allow": {
                            "operation_type": r.operation_type,
                            "operation_name": r.operation_name,
                            "fields": list(r.fields),
                        }
                    }
                    for r in selected
                ]
            else:
                versions = {r.versions for r in selected}
                if len(versions) != 1:
                    unsupported.add("network.mcp_version_conflict")
                    continue
                protocol_endpoint["mcp"] = {
                    "strict_tool_names": True,
                    "allow_all_known_mcp_methods": False,
                    "versions": list(selected[0].versions),
                }
                protocol_endpoint["rules"] = [
                    {
                        "allow": {
                            "method": r.method,
                            **({"params": {"name": {"any": [r.tool]}}} if r.tool else {}),
                        }
                    }
                    for r in selected
                ]
            rules[f"ordin_action_{contract.action_digest[:12]}_{index}"] = {
                "endpoints": [protocol_endpoint],
                "binaries": [{"path": p} for p in executables],
            }
            continue
        if capability.protocol != "rest" or capability.tool_identity is not None:
            unsupported.add("network.protocol")
            continue
        if not exact_host(capability.host) or type(capability.port) is not int:
            unsupported.add("network.endpoint_identity")
            continue
        if capability.access not in {"read", "write"} or (
            capability.access == "read" and not set(capability.methods).issubset(READ_METHODS)
        ):
            unsupported.add("network.access")
        if (
            not capability.methods
            or not capability.paths
            or any(not exact_request_path(p) for p in capability.paths)
        ):
            unsupported.add("network.request_scope")
            continue
        endpoint: dict[str, Any] = {
            "host": capability.host,
            "port": capability.port,
            "protocol": "rest",
            "enforcement": "enforce",
            "allowed_ips": list(PUBLIC_IPV4_RANGES),
            "rules": [
                {"allow": {"method": m, "path": p}}
                for m in sorted(set(capability.methods))
                for p in sorted(set(capability.paths))
            ],
        }
        matching = [
            c
            for c in contract.credentials
            if c.host == capability.host and c.port == capability.port
        ]
        if len(matching) > 1:
            unsupported.add("credentials.multiple_bindings")
        for credential in matching:
            provider = (credential_providers or {}).get(credential.binding)
            if (
                not isinstance(provider, Mapping)
                or set(provider) != {"provider", "host", "port", "methods", "paths"}
                or (
                    provider["host"] != credential.host
                    or provider["port"] != credential.port
                    or not set(capability.methods).issubset(provider["methods"])
                    or not set(capability.paths).issubset(provider["paths"])
                    or not isinstance(provider["provider"], str)
                    or not provider["provider"]
                )
            ):
                unsupported.add("credential_binding_unknown")
            else:
                endpoint["credential_binding"] = {"provider": provider["provider"]}
        rules[f"ordin_action_{contract.action_digest[:12]}_{index}"] = {
            "endpoints": [endpoint],
            "binaries": [{"path": p} for p in executables],
        }
    for credential in contract.credentials:
        if not any(
            n.host == credential.host and n.port == credential.port for n in contract.network
        ):
            unsupported.add("credentials.endpoint_missing")
    policy = {
        "version": 1,
        "filesystem_policy": {"include_workdir": False, "read_only": ro, "read_write": rw},
        "landlock": {"compatibility": "hard_requirement"},
        "process": {
            "run_as_user": str(process_identity[0]),
            "run_as_group": str(process_identity[1]),
        }
        if process_identity
        else {},
        "network_policies": rules,
    }
    if base_policy is not None and thaw(base_policy) != policy:
        # Preserve only a base already equal to this exact authority. Composing
        # arbitrary provider/default grants would invalidate the contract bound.
        unsupported.add("base_policy.would_widen_or_change_authority")
    unsupported.update(policy_errors(policy))
    if unsupported:
        return CompilationResult(
            "unsupported",
            "openshell",
            "openshell_compiler_unrepresentable",
            unsupported_fields=tuple(sorted(unsupported)),
        )
    plan = EnforcementPlan(
        "openshell",
        contract,
        policy,
        mode=mode,
        metadata={
            "integration_version": "0.1.0",
            "backend_version": "0.1.2",
            "policy_schema_version": 1,
            "semantic_effects": thaw(contract.source.get("effects", ())),
            "source_provenance_digest": contract.source.get("provenance_digest"),
            "resource_kinds": dict(resource_kinds or {}),
            "credential_binding_ids": [c.binding for c in contract.credentials],
            **(
                {
                    "request_contract": request_contract.as_dict(),
                    "request_contract_digest": request_contract.digest,
                }
                if request_contract
                else {}
            ),
        },
    )
    return CompilationResult("success", "openshell", "openshell_compiler_complete", plan=plan)


@dataclass(frozen=True)
class OpenShellBackend:
    process_identity: tuple[int, int] | None = None
    resource_kinds: Mapping[str, str] = field(default_factory=dict)
    credential_providers: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    mode: str = "enforce"
    request_contract: RuntimeRequestContract | None = None

    @property
    def name(self) -> str:
        return "openshell"

    def compile(self, contract: RuntimeCapabilityContract) -> CompilationResult:
        return compile_openshell_policy(
            contract,
            process_identity=self.process_identity,
            resource_kinds=self.resource_kinds,
            credential_providers=self.credential_providers,
            mode=self.mode,
            request_contract=self.request_contract,
        )

    def validate(self, plan: EnforcementPlan) -> BackendValidationResult:
        if plan.backend != self.name:
            return BackendValidationResult(
                "invalid", self.name, plan.policy_digest, "openshell_backend_mismatch"
            )
        fields = policy_errors(plan.policy)
        if not fields:
            rebuilt = compile_openshell_policy(
                plan.contract,
                process_identity=self.process_identity,
                resource_kinds=self.resource_kinds,
                credential_providers=self.credential_providers,
                mode=self.mode,
                request_contract=self.request_contract,
            )
            if (
                rebuilt.status != "success"
                or rebuilt.plan is None
                or rebuilt.plan.policy_digest != plan.policy_digest
                or rebuilt.plan.metadata != plan.metadata
            ):
                fields = ("policy.contract_authority_mismatch",)
        return BackendValidationResult(
            "unsupported" if fields else "success",
            self.name,
            plan.policy_digest,
            "openshell_policy_unsupported" if fields else "openshell_policy_valid",
            unsupported_fields=fields,
        )
