from __future__ import annotations

import json
import re
from pathlib import Path
from string import Formatter
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCHEMA_DIR = ROOT / "schemas"
PACKAGE_SCHEMA_DIR = Path(__file__).resolve().parent / "resources" / "schemas"
# A sibling site-packages/schemas directory can belong to another distribution.
# Runtime validation uses the resources owned by this Ordin package; source
# schemas remain available for the checkout parity checks below.
SCHEMA_DIR = PACKAGE_SCHEMA_DIR
SOURCE_DATA_DIR = ROOT / "data"
PACKAGE_DATA_DIR = Path(__file__).resolve().parent / "resources"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
VALID_RISKS = {"unknown", "low", "medium", "high", "critical"}
KNOWN_TEMPLATE_FIELDS = {
    "url",
    "host",
    "port",
    "pattern",
    "path",
    "depth",
    "package",
    "process",
    "branch",
}
SCHEMA_FILES = {
    "swarm_release_manifest": "swarm-release-manifest.v1.schema.json",
    "swarm_approval_policy": "swarm-approval-policy.v1.schema.json",
    "swarm_approval": "swarm-approval.v1.schema.json",
    "swarm_recovery_request": "swarm-recovery-request.v1.schema.json",
    "swarm_approval_receipt": "swarm-approval-receipt.v1.schema.json",
    "swarm_approval_resolution": "swarm-approval-resolution.v1.schema.json",
    "swarm_approval_queue": "swarm-approval-queue.v1.schema.json",
    "swarm_approval_audit": "swarm-approval-audit.v1.schema.json",
    "approval_scope": "approval-scope.v1.schema.json",
    "approval_satisfaction": "approval-satisfaction.v1.schema.json",
    "approval_execution_lease": "approval-execution-lease.v1.schema.json",
    "swarm_owned_demo": "swarm-owned-demo.v1.schema.json",
    "swarm_quickstart": "swarm-quickstart.v1.schema.json",
    "swarm_artifact": "swarm-artifact.v1.schema.json",
    "swarm_artifact_diagnostics": "swarm-artifact-diagnostics.v1.schema.json",
    "swarm_audit_event": "swarm-audit-event.v1.schema.json",
    "swarm_audit_bundle": "swarm-audit-bundle.v1.schema.json",
    "swarm_audit_checkpoint": "swarm-audit-checkpoint.v1.schema.json",
    "swarm_audit_verification": "swarm-audit-verification.v1.schema.json",
    "swarm_operator_snapshot": "swarm-operator-snapshot.v1.schema.json",
    "swarm_operator_list": "swarm-operator-list.v1.schema.json",
    "swarm_operator_view": "swarm-operator-view.v1.schema.json",
    "swarm_operator_explanation": "swarm-operator-explanation.v1.schema.json",
    "swarm_operator_control": "swarm-operator-control.v1.schema.json",
    "swarm_artifact_retention": "swarm-artifact-retention.v1.schema.json",
    "swarm_operator_retention": "swarm-operator-retention.v1.schema.json",
    "swarm_operator_request": "swarm-operator-request.v1.schema.json",
    "swarm_operator_response": "swarm-operator-response.v1.schema.json",
    "swarm_operator_unconfigured": "swarm-operator-unconfigured.v1.schema.json",
    "swarm_otel_export": "swarm-otel-export.v1.schema.json",
    "swarm_ocsf_export": "swarm-ocsf-export.v1.schema.json",
    "audit_checkpoint": "audit-checkpoint.v1.schema.json",
    "trace_checkpoint": "trace-checkpoint.v1.schema.json",
    "swarm_incident": "swarm-incident.v1.schema.json",
    "swarm_corpus": "swarm-corpus.v1.schema.json",
    "swarm_corpus_report": "swarm-corpus-report.v1.schema.json",
    "swarm_overhead_report": "swarm-overhead-report.v1.schema.json",
    "swarm_framework_fixture": "swarm-framework-fixture.v1.schema.json",
    "swarm_framework_preparation": "swarm-framework-preparation.v1.schema.json",
    "swarm_framework_result": "swarm-framework-result.v1.schema.json",
    "swarm_framework_session": "swarm-framework-session.v1.schema.json",
    "swarm_framework_adapter": "swarm-framework-adapter.v1.schema.json",
    "swarm_framework_installation": "swarm-framework-installation.v1.schema.json",
    "swarm_framework_setup": "swarm-framework-setup.v1.schema.json",
    "swarm_coordinator_record": "swarm-coordinator-record.v1.schema.json",
    "swarm_coordinator_fence": "swarm-coordinator-fence.v1.schema.json",
    "swarm_coordinator_dispatch": "swarm-coordinator-dispatch.v1.schema.json",
    "swarm_coordinator_status": "swarm-coordinator-status.v1.schema.json",
    "swarm_coordinator_offline": "swarm-coordinator-offline.v1.schema.json",
    "swarm_coordinator_policy": "swarm-coordinator-policy.v1.schema.json",
    "swarm_coordinator_producer": "swarm-coordinator-producer.v1.schema.json",
    "swarm_coordinator_revocation": "swarm-coordinator-revocation.v1.schema.json",
    "swarm_coordinator_request": "swarm-coordinator-request.v1.schema.json",
    "swarm_coordinator_response": "swarm-coordinator-response.v1.schema.json",
    "swarm_broker_preparation": "swarm-broker-preparation.v1.schema.json",
    "swarm_broker_scope": "swarm-broker-scope.v1.schema.json",
    "swarm_broker_result": "swarm-broker-result.v1.schema.json",
    "swarm_broker_control": "swarm-broker-control.v1.schema.json",
    "swarm_executor_outcome": "swarm-executor-outcome.v1.schema.json",
    "swarm_risk_context": "swarm-risk-context.v1.schema.json",
    "swarm_risk_signal": "swarm-risk-signal.v1.schema.json",
    "swarm_risk_receipt": "swarm-risk-receipt.v1.schema.json",
    "swarm_risk_calibration": "swarm-risk-calibration.v1.schema.json",
    "swarm_policy_validation": "swarm-policy-validation.v1.schema.json",
    "swarm_policy_set": "swarm-policy-set.v1.schema.json",
    "swarm_policy_maximum": "swarm-policy-maximum.v1.schema.json",
    "swarm_policy_compilation": "swarm-policy-compilation.v1.schema.json",
    "swarm_policy_simulation": "swarm-policy-simulation.v1.schema.json",
    "swarm_policy_activation": "swarm-policy-activation.v1.schema.json",
    "swarm_policy_diff": "swarm-policy-diff.v1.schema.json",
    "swarm_temporal_validation": "swarm-temporal-validation.v1.schema.json",
    "swarm_temporal_policy_set": "swarm-temporal-policy-set.v1.schema.json",
    "swarm_temporal_evaluation": "swarm-temporal-evaluation.v1.schema.json",
    "swarm_budget": "swarm-budget.v1.schema.json",
    "swarm_budget_reservation": "swarm-budget-reservation.v1.schema.json",
    "swarm_budget_audit": "swarm-budget-audit.v1.schema.json",
    "swarm_remote_delegation": "swarm-remote-delegation.v1.schema.json",
    "swarm_remote_review": "swarm-remote-review.v1.schema.json",
    "swarm_delegation_dispatch": "swarm-delegation-dispatch.v1.schema.json",
    "swarm_broker_admission_scope": "swarm-broker-admission-scope.v1.schema.json",
    "swarm_authority_audit": "swarm-authority-audit.v1.schema.json",
    "swarm_credential_audit": "swarm-credential-audit.v1.schema.json",
    "swarm_message_peer_status": "swarm-message-peer-status.v1.schema.json",
    "swarm_message": "swarm-message.v1.schema.json",
    "swarm_message_outcome": "swarm-message-outcome.v1.schema.json",
    "swarm_source_flow": "swarm-source-flow.v1.schema.json",
    "swarm_attach_status": "swarm-attach-status.v1.schema.json",
    "swarm_attach_plan": "swarm-attach-plan.v1.schema.json",
    "swarm_causal_graph": "swarm-causal-graph.v1.schema.json",
    "swarm_gateway_status": "swarm-gateway-status.v1.schema.json",
    "swarm_decision": "swarm-decision.v1.schema.json",
    "swarm_event": "swarm-event.v1.schema.json",
    "swarm_context": "swarm-context.v1.schema.json",
    "assurance_semantic_simulation": "assurance-semantic-simulation.v1.schema.json",
    "assurance_linux_sandbox_test": "assurance-linux-sandbox-test.v1.schema.json",
    "assurance_boundary_regression": "assurance-boundary-regression.v1.schema.json",
    "assurance_rest_semantics": "assurance-rest-semantics.v1.schema.json",
    "assurance_rest_authority": "assurance-rest-authority.v1.schema.json",
    "assurance_rest_boundary": "assurance-rest-boundary.v1.schema.json",
    "assurance_rest_contract": "assurance-rest-contract.v1.schema.json",
    "assurance_profile_inspection": "assurance-profile-inspection.v1.schema.json",
    "assurance_invariant_preview": "assurance-invariant-preview.v1.schema.json",
    "assurance_attack_path_inspection": "assurance-attack-path-inspection.v1.schema.json",
    "assurance_delegation_inspection": "assurance-delegation-inspection.v1.schema.json",
    "assurance_static_finding_review": "assurance-static-finding-review.v1.schema.json",
    "assurance_challenge_catalog": "assurance-challenge-catalog.v1.schema.json",
    "assurance_workflow_capture": "assurance-workflow-capture.v1.schema.json",
    "assurance_workflow_claim": "assurance-workflow-claim.v1.schema.json",
    "assurance_workflow_import": "assurance-workflow-import.v1.schema.json",
    "assurance_source_fix": "assurance-source-fix.v1.schema.json",
    "assurance_synthetic_path_suite": "assurance-synthetic-path-suite.v1.schema.json",
    "assurance_vetted_program": "assurance-vetted-program.v1.schema.json",
    "assurance_sandbox_test": "assurance-sandbox-test.v1.schema.json",
    "assurance_contract_authorization": "assurance-contract-authorization.v1.schema.json",
    "assurance_source_patch": "assurance-source-patch.v1.schema.json",
    "assurance_remediation_proposal": "assurance-remediation-proposal.v1.schema.json",
    "assurance_fix_verification": "assurance-fix-verification.v1.schema.json",
    "assurance_finding_review": "assurance-finding-review.v1.schema.json",
    "assurance_replay_input": "assurance-replay-input.v1.schema.json",
    "assurance_finding_validation": "assurance-finding-validation.v1.schema.json",
    "assurance_host_credential_use": "assurance-host-credential-use.v1.schema.json",
    "assurance_host_approval": "assurance-host-approval.v1.schema.json",
    "assurance_host_assessment": "assurance-host-assessment.v1.schema.json",
    "assurance_host_context": "assurance-host-context.v1.schema.json",
    "assurance_decision": "assurance-decision.v1.schema.json",
    "assurance_repository_inventory": "assurance-repository-inventory.v1.schema.json",
    "assurance_repository_threat_model": "assurance-repository-threat-model.v1.schema.json",
    "assurance_profile_compilation": "assurance-profile-compilation.v1.schema.json",
    "assurance_security_profile": "assurance-security-profile.v1.schema.json",
    "assurance_security_profile_draft": "assurance-security-profile-draft.v1.schema.json",
    "assurance_invariant": "assurance-invariant.v1.schema.json",
    "assurance_invariant_evaluation": "assurance-invariant-evaluation.v1.schema.json",
    "assurance_finding": "assurance-finding.v1.schema.json",
    "assurance_attack_path": "assurance-attack-path.v1.schema.json",
    "assurance_simulation": "assurance-simulation.v1.schema.json",
    "assurance_challenge_run": "assurance-challenge-run.v1.schema.json",
    "assurance_challenge_suite": "assurance-challenge-suite.v1.schema.json",
    "assurance_solver_challenge": "assurance-solver-challenge.v1.schema.json",
    "assurance_instruction_origin": "assurance-instruction-origin.v1.schema.json",
    "assurance_source_use": "assurance-source-use.v1.schema.json",
    "assurance_source_provenance": "assurance-source-provenance.v1.schema.json",
    "assurance_delegation_verification": "assurance-delegation-verification.v1.schema.json",
    "assurance_delegated_decision": "assurance-delegated-decision.v1.schema.json",
    "assurance_imported_finding": "assurance-imported-finding.v1.schema.json",
    "assurance_scan_import": "assurance-scan-import.v1.schema.json",
    "assurance_scanner_run": "assurance-scanner-run.v1.schema.json",
    "assurance_security_questions": "assurance-security-questions.v1.schema.json",
    "assurance_semantic_state": "assurance-semantic-state.v1.schema.json",
    "assurance_semantic_policy": "assurance-semantic-policy.v1.schema.json",
    "assurance_semantic_decision": "assurance-semantic-decision.v1.schema.json",
    "assurance_semantic_inspection": "assurance-semantic-inspection.v1.schema.json",
    "assurance_diff_triage": "assurance-diff-triage.v1.schema.json",
    "assurance_counterexample": "assurance-counterexample.v1.schema.json",
    "assurance_delegation": "assurance-delegation.v1.schema.json",
    "assurance_model_evidence": "assurance-model-evidence.v1.schema.json",
    "runtime_request_contract": "runtime-request-contract.v1.schema.json",
    "runtime_request_boundary": "runtime-request-boundary.v1.schema.json",
    "runtime_request_contract_v2": "runtime-request-contract.v2.schema.json",
    "runtime_request_boundary_v2": "runtime-request-boundary.v2.schema.json",
    "runtime_shadow_report": "runtime-shadow-report.v1.schema.json",
    "capability_delta_proposal": "capability-delta-proposal.v1.schema.json",
    "runtime_capability_boundary": "runtime-capability-boundary.v1.schema.json",
    "runtime_session": "runtime-session.v1.schema.json",
    "runtime_observation": "runtime-observation.v1.schema.json",
    "runtime_observation_history": "runtime-observation-history.v1.schema.json",
    "runtime_capability": "runtime-capability.v1.schema.json",
    "cursor_mcp_map": "cursor-mcp-map.v1.schema.json",
    "action_trace": "action-trace.v1.schema.json",
    "trace_event": "trace-event.v1.schema.json",
    "trace_candidate": "trace-candidate.v1.schema.json",
    "codex_mcp_map": "codex-mcp-map.v1.schema.json",
    "mcp_inventory": "mcp-inventory.v1.schema.json",
    "mcp_contract_lock": "mcp-contract-lock.v1.schema.json",
    "integration_session": "integration-session.v1.schema.json",
    "command_card": "command-card.v1.schema.json",
    "search_result": "search-result.v1.schema.json",
    "risk_review": "risk-review.v1.schema.json",
    "review_result": "review-result.v1.schema.json",
    "action_envelope": "action-envelope.v1.schema.json",
    "action_history": "action-history.v1.schema.json",
    "action_review": "action-review.v1.schema.json",
    "execution_capabilities": "execution-capabilities.v1.schema.json",
    "action_observation": "action-observation.v1.schema.json",
    "observation_history": "observation-history.v1.schema.json",
    "provenance": "provenance.v1.schema.json",
    "audit_event": "audit-event.v1.schema.json",
    "policy_set": "policy-set.v1.schema.json",
    "temporal_policy_set": "temporal-policy-set.v1.schema.json",
    "tool_semantics": "tool-semantics.v1.schema.json",
    "review_request": "review-request.v1.schema.json",
    "risk_rules": "risk-rules.v1.schema.json",
    "effect_catalog": "effect-catalog.v1.schema.json",
    "effect_graph": "effect-graph.v1.schema.json",
    "command_pack": "command-pack.v1.schema.json",
    "pack_list": "pack-list.v1.schema.json",
}


def load_schema(name: str) -> dict[str, Any]:
    filename = SCHEMA_FILES.get(name, name)
    path = SCHEMA_DIR / filename
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"schema {filename!r} must contain a JSON object")
    return payload


def _type_matches(instance: Any, expected: str) -> bool:
    if expected == "null":
        return instance is None
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "object":
        return isinstance(instance, dict)
    return True


def validate_instance(
    instance: Any,
    schema: dict[str, Any],
    path: str = "$",
) -> list[str]:
    errors: list[str] = []

    expected_type = schema.get("type")
    if expected_type is not None:
        expected = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(isinstance(item, str) and _type_matches(instance, item) for item in expected):
            errors.append(f"{path}: expected type {expected_type!r}")
            return errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value {instance!r} is not in enum")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            errors.append(f"{path}: string is shorter than {min_length}")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(instance) > max_length:
            errors.append(f"{path}: string is longer than {max_length}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                if re.search(pattern, instance) is None:
                    errors.append(f"{path}: string does not match pattern {pattern!r}")
            except re.error as exc:
                errors.append(f"{path}: schema has invalid pattern: {exc}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            errors.append(f"{path}: value is below minimum {minimum}")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and instance > maximum:
            errors.append(f"{path}: value is above maximum {maximum}")

    if isinstance(instance, list):
        if schema.get("uniqueItems") is True:
            # JSON booleans are distinct from numbers, unlike Python equality.
            def key(value: Any) -> Any:
                if isinstance(value, dict):
                    return ("object", tuple(sorted((k, key(v)) for k, v in value.items())))
                if isinstance(value, list):
                    return ("array", tuple(key(v) for v in value))
                if isinstance(value, bool):
                    return ("boolean", value)
                if isinstance(value, (int, float)):
                    return ("number", value)
                return (type(value).__name__, value)

            if len({key(value) for value in instance}) != len(instance):
                errors.append(f"{path}: array items must be unique")
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            errors.append(f"{path}: array has fewer than {min_items} items")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(instance) > max_items:
            errors.append(f"{path}: array has more than {max_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(instance):
                errors.extend(validate_instance(value, item_schema, f"{path}[{index}]"))

    if isinstance(instance, dict):
        max_properties = schema.get("maxProperties")
        if isinstance(max_properties, int) and len(instance) > max_properties:
            errors.append(f"{path}: object has more than {max_properties} properties")
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        for key, value in instance.items():
            if key in properties and isinstance(properties[key], dict):
                errors.extend(validate_instance(value, properties[key], f"{path}.{key}"))
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(additional, dict):
                errors.extend(validate_instance(value, additional, f"{path}.{key}"))

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        branch_errors = [
            validate_instance(instance, branch, path)
            for branch in any_of
            if isinstance(branch, dict)
        ]
        if branch_errors and not any(not item for item in branch_errors):
            errors.append(f"{path}: value does not satisfy anyOf")

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        successes = sum(
            not validate_instance(instance, branch, path)
            for branch in one_of
            if isinstance(branch, dict)
        )
        if successes != 1:
            errors.append(f"{path}: value must satisfy exactly one oneOf branch")

    return errors


def validate_named_schema(name: str, instance: Any) -> list[str]:
    return validate_instance(instance, load_schema(name))


def validate_schema_files() -> list[str]:
    errors: list[str] = []
    shipped = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}
    if shipped != set(SCHEMA_FILES.values()):
        errors.append("schema registry and shipped schema files differ")
    supported = {
        "$schema",
        "$id",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "minItems",
        "maxItems",
        "uniqueItems",
        "maxProperties",
        "anyOf",
        "oneOf",
    }
    for name, filename in SCHEMA_FILES.items():
        try:
            schema = load_schema(name)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"schema {filename}: {exc}")
            continue
        from ._runtime_schemas import SCHEMAS as runtime_schemas

        if name in runtime_schemas and schema != runtime_schemas[name]:
            errors.append(f"schema {filename}: differs from runtime validation definition")
        if name.startswith("assurance_"):
            from .assurance._schemas import SCHEMAS as assurance_schemas

            if schema != assurance_schemas.get(name):
                errors.append(f"schema {filename}: differs from assurance validation definition")
        if schema.get("$schema") != DRAFT_2020_12:
            errors.append(f"schema {filename}: expected Draft 2020-12 declaration")
        if not isinstance(schema.get("$id"), str) or not schema["$id"]:
            errors.append(f"schema {filename}: missing $id")
        if schema.get("type") != "object":
            errors.append(f"schema {filename}: top-level type must be object")
        pending = [schema]
        while pending:
            node = pending.pop()
            if set(node) - supported:
                errors.append(
                    f"schema {filename}: unsupported validation keywords {sorted(set(node) - supported)}"
                )
            properties = node.get("properties", {})
            if isinstance(properties, dict):
                pending.extend(value for value in properties.values() if isinstance(value, dict))
            for name in ("items", "additionalProperties"):
                if isinstance(node.get(name), dict):
                    pending.append(node[name])
            for name in ("anyOf", "oneOf"):
                pending.extend(value for value in node.get(name, []) if isinstance(value, dict))
    return errors


def validate_command_card_schemas(commands: Iterable[dict[str, Any]]) -> list[str]:
    schema = load_schema("command_card")
    errors: list[str] = []
    for entry in commands:
        name = entry.get("command", "<unknown>")
        for error in validate_instance(entry, schema):
            errors.append(f"command {name}: {error}")
    return errors


def validate_risk_rule_semantics(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        return ["risk rules payload: rules must be a list"]
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"risk rule {index}: must be an object")
            continue
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            if rule_id in seen:
                errors.append(f"risk rule {rule_id}: duplicate id")
            seen.add(rule_id)
        pattern = rule.get("pattern")
        if isinstance(pattern, str):
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"risk rule {rule_id or index}: invalid regex: {exc}")
        if rule.get("risk") not in VALID_RISKS - {"unknown"}:
            errors.append(f"risk rule {rule_id or index}: invalid risk {rule.get('risk')!r}")
    return errors


def _template_fields(template: str) -> set[str]:
    result: set[str] = set()
    for _, field_name, _, _ in Formatter().parse(template):
        if field_name:
            result.add(field_name)
    return result


def validate_template_semantics(commands: Iterable[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for entry in commands:
        command = entry.get("command", "<unknown>")
        templates = entry.get("templates", [])
        if not isinstance(templates, list):
            errors.append(f"command {command}: templates must be a list")
            continue
        for index, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            text = template.get("command")
            if not isinstance(text, str):
                continue
            try:
                fields = _template_fields(text)
            except ValueError as exc:
                errors.append(f"command {command} template {index}: invalid format: {exc}")
                continue
            unknown = sorted(fields - KNOWN_TEMPLATE_FIELDS)
            if unknown:
                errors.append(
                    f"command {command} template {index}: unknown template fields "
                    + ", ".join(unknown)
                )
            defaults = template.get("safe_defaults", {})
            if defaults is not None and not isinstance(defaults, dict):
                errors.append(
                    f"command {command} template {index}: safe_defaults must be an object"
                )
            elif isinstance(defaults, dict):
                extra_defaults = sorted(set(defaults) - fields)
                if extra_defaults:
                    errors.append(
                        f"command {command} template {index}: safe_defaults reference "
                        + ", ".join(extra_defaults)
                    )
    return errors


def _compare_json_tree(
    source_root: Path,
    package_root: Path,
    label: str,
    *,
    ignored_package_roots: set[str] | None = None,
) -> list[str]:
    ignored = ignored_package_roots or set()
    errors: list[str] = []
    source_files = {
        path.relative_to(source_root) for path in source_root.rglob("*.json") if path.is_file()
    }
    package_files = {
        path.relative_to(package_root)
        for path in package_root.rglob("*.json")
        if path.is_file()
        and not (
            path.relative_to(package_root).parts
            and path.relative_to(package_root).parts[0] in ignored
        )
    }
    for relative in sorted(source_files | package_files):
        source_path = source_root / relative
        package_path = package_root / relative
        if relative not in package_files:
            errors.append(f"packaged {label} missing: {relative.as_posix()}")
            continue
        if relative not in source_files:
            errors.append(f"packaged {label} has extra file: {relative.as_posix()}")
            continue
        try:
            source_payload = json.loads(source_path.read_text(encoding="utf-8"))
            package_payload = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{label} {relative.as_posix()}: {exc}")
            continue
        if source_payload != package_payload:
            errors.append(f"packaged {label} differs from source: {relative.as_posix()}")
    return errors


def resource_parity_errors() -> list[str]:
    if not SOURCE_DATA_DIR.exists() or not PACKAGE_DATA_DIR.exists():
        return []
    errors = _compare_json_tree(
        SOURCE_DATA_DIR,
        PACKAGE_DATA_DIR,
        "resource",
        ignored_package_roots={"schemas", "swarm"},
    )
    corpus_source = ROOT / "benchmarks" / "swarm" / "v1"
    if corpus_source.exists():
        errors.extend(
            _compare_json_tree(corpus_source, PACKAGE_DATA_DIR / "swarm" / "v1", "swarm corpus")
        )
    if SOURCE_SCHEMA_DIR.exists() and PACKAGE_SCHEMA_DIR.exists():
        errors.extend(
            _compare_json_tree(
                SOURCE_SCHEMA_DIR,
                PACKAGE_SCHEMA_DIR,
                "schema",
            )
        )
    return sorted(set(errors))
