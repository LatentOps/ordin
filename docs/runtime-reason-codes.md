# Runtime reason codes

Machine codes are stable identifiers; prose is explanatory and may change.
Non-success states preserve unsupported fields and verification coverage.

| Code | Meaning / required handling |
| --- | --- |
| `runtime_contract_unknown_semantics` | No deterministic semantic binding; diagnostic authority only. |
| `runtime_contract_missing_resource` | A required resource/identity is not established. |
| `runtime_contract_malformed_resource` | Resource syntax is ambiguous or contains sensitive URL components. |
| `runtime_contract_unknown_protocol` | Host information does not establish request restrictions. |
| `runtime_contract_conflicting_requirement` | Reviewed runtime facts conflict; refuse compilation. |
| `runtime_contract_mcp_version_unapproved` | Requested MCP revision lacks an explicit matching host declaration; retain diagnostic state. |
| `runtime_boundary_blocked_decision` | A blocked semantic review cannot pass for granting authority. |
| `filesystem_access_exceeds_boundary` | Access/resource falls outside allowed filesystem grants. |
| `network_request_exceeds_boundary` | Method/path pair is outside the caller's network boundary. |
| `credential_binding_exceeds_boundary` | Credential authorization is independent and not present. |
| `openshell_compiler_unrepresentable` | No complete plan can represent the contract without widening. Inspect all unsupported fields. |
| `openshell_operator_configuration_invalid` | Operator metadata has unsupported fields or values; nothing is copied into a plan. |
| `credential_binding_unknown` | No exact trusted provider/destination restriction mapping. |
| `openshell_prover_missing` | Configured standalone verifier is absent. |
| `openshell_prover_coverage_incomplete` | Required domains were not verified; success is refused. |
| `openshell_prover_compatibility` | Unknown prover schema/version/result shape. |
| `openshell_prover_input_binding_mismatch` | Proof does not bind the actual candidate/boundary bytes. |
| `openshell_apply_requires_approval` | Exact current request requires explicit host approval. |
| `openshell_apply_startup_policy_mismatch` | Live network apply cannot change startup filesystem/process/Landlock controls. |
| `openshell_policy_drift` | Readback differs from verified/approved state. No retry or action execution. |
| `openshell_policy_not_loaded` | Effective configuration and loaded revision do not agree. |
| `openshell_policy_not_admitted` | Workload admission does not agree with current policy. |
| `runtime_observation_action_mismatch` | Unknown/changed action identity or canonical digest; reject attachment. |
| `runtime_observation_contract_mismatch` | Evidence references a different contract. |
| `runtime_observation_session_mismatch` | Reporting session/reset epoch differs. |
| `runtime_observation_duplicate` | Consumed or duplicate evidence identity. |
| `runtime_observation_untrusted_source` | Ordinary JSON cannot declare strong backend labels. |
| `runtime_delta_unmodeled_requirement` | Denial requests authority absent from semantic prediction; investigate. |
| `runtime_delta_requires_approval` | Narrow proposal still needs human approval. |
| `runtime_delta_backend_proof_rejected` | Backend proof or snapshot correlation failed; no candidate plan. |

Boundary results remain `within_boundary`, `exceeds_boundary`, `unsupported`, and
`inconclusive`; only `within_boundary` succeeds. Backend errors/timeouts are
separate non-success states. OCSF unsupported classes/protocols and uncorrelated
events do not silently enter an action trajectory. A policy-submit timeout can
leave runtime state uncertain and must never trigger automatic resubmission.
