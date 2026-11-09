"""No-widening Ordin Runtime policy admission using the existing native verifier.

Management apply/readback is not a completion receipt and cannot satisfy the
owned executor ABI. An arbitrary callback cannot promote it into enforcement.
"""

from __future__ import annotations

from typing import Any
from ordin._runtime_json import freeze, thaw

from ordin.enforcement_backend import CompilationResult
from ordin.runtime_contract import RuntimeCapabilityContract
from ordin.runtime_requests import RuntimeRequestContract
from ordin.runtime_requests_v2 import RuntimeRequestContractV2


class SwarmRuntimeBackend:
    def __init__(
        self,
        backend,
        cli,
        *,
        sandbox: str,
        capability_boundary,
        backend_boundary_policy,
        request_boundary=None,
        prover_executable="openshell-prover",
        operator: object,
    ):
        from ordin_runtime import OrdinRuntimeBackend
        from ordin_runtime.backend_cli import RuntimeCLI, identifier

        if (
            type(backend) is not OrdinRuntimeBackend
            or type(cli) is not RuntimeCLI
            or type(operator) is not object
        ):
            raise ValueError("original protected Ordin Runtime backend and management CLI required")
        identifier(sandbox)
        if capability_boundary is None or backend_boundary_policy is None:
            raise ValueError("explicit full capability and native backend maximum required")
        self.backend, self.cli, self.sandbox = backend, cli, sandbox
        self.capability_boundary, self.backend_boundary_policy = (
            capability_boundary,
            thaw(freeze(backend_boundary_policy, max_depth=12)),
        )
        self.request_boundary, self.prover_executable = request_boundary, prover_executable
        self._operator = operator
        self._plans: dict[int, Any] = {}

    def compile(self, requirement):
        if type(requirement) in {RuntimeRequestContract, RuntimeRequestContractV2}:
            configured = self.backend.request_contract
            if (
                configured is None
                or configured.digest != requirement.digest
                or self.request_boundary is None
            ):
                return CompilationResult(
                    "unsupported",
                    "openshell",
                    "swarm.openshell_exact_request_binding_required",
                    unsupported_fields=("requests.complete_authority",),
                )
            capability = requirement.capability
        elif type(requirement) is RuntimeCapabilityContract:
            if self.backend.request_contract is not None:
                return CompilationResult(
                    "unsupported",
                    "openshell",
                    "swarm.openshell_request_authority_omitted",
                    unsupported_fields=("requests.complete_authority",),
                )
            capability = requirement
        else:
            # In particular, never strip an exact REST composite into TCP or a
            # diagnostic capability that the existing backend cannot execute.
            return CompilationResult(
                "unsupported",
                "openshell",
                "swarm.openshell_requirement_unrepresentable",
                unsupported_fields=("requirements.complete_authority",),
            )
        if any(v.protocol == "rest" for v in capability.network):
            return CompilationResult(
                "unsupported",
                "openshell",
                "swarm.openshell_exact_rest_authority_required",
                unsupported_fields=("requests.rest_complete_authority",),
            )
        result = self.backend.compile(capability)
        if result.plan is not None and result.enforceable:
            if len(self._plans) >= 4096:
                return CompilationResult(
                    "unsupported", "openshell", "swarm.openshell_plan_capacity_reached"
                )
            self._plans[id(result.plan)] = result.plan
        return result

    def validate(self, plan):
        return self.backend.validate(plan)

    def _arguments(self, plan):
        if self._plans.get(id(plan)) is not plan:
            raise ValueError("original complete Ordin Runtime compilation required")
        return dict(
            backend=self.backend,
            sandbox=self.sandbox,
            cli=self.cli,
            capability_boundary=self.capability_boundary,
            backend_boundary_policy=self.backend_boundary_policy,
            request_boundary=self.request_boundary,
            prover_executable=self.prover_executable,
        )

    def prepare(self, plan):
        from ordin_runtime.apply import prepare_runtime_apply

        # The existing verifier compares actual admitted startup state: a live
        # filesystem/process restriction returns requires_restart/unsupported.
        return prepare_runtime_apply(plan, **self._arguments(plan))

    def apply(self, plan, *, approval_request_id: str, operator: object):
        from ordin_runtime.apply import apply_runtime_policy

        if operator is not self._operator:
            raise ValueError("protected Ordin Runtime operator required")
        return apply_runtime_policy(
            plan, approval_request_id=approval_request_id, **self._arguments(plan)
        )
