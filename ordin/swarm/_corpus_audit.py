"""Independent provenance controls over original producers and synthetic data."""

from dataclasses import replace
import json

from ordin import AgentGate
from ordin._runtime_json import digest

from ._corpus_runtime import owned_runtime
from .audit import SwarmAuditJournal, TenantRedactor, verify_swarm_audit
from .diagnostics import SwarmAuditSource
from .gate import SwarmGate


def run_audit(name, *, workspace):
    from .corpus_controls import outcome

    kernel = name == "kernel-audit-provenance"
    with owned_runtime(workspace / "authority", kernel=kernel) as runtime:
        coordinator, scope, control, lease = runtime.coordinate()
        key = b"PUBLIC_SYNTHETIC_AUDIT_KEY_276_32_BYTES"
        journal = SwarmAuditJournal(
            workspace / "audit.sqlite",
            key=key,
            tenant_id="corpus-tenant",
            operator=runtime.operator,
            clock=coordinator.clock,
            create=True,
        )
        source = SwarmAuditSource(
            journal,
            coordinator,
            scope,
            control=control,
            operator=runtime.operator,
        )
        try:
            source.record_risk(
                severity="critical",
                confidence=0.99,
                model_ref="synthetic-diagnostic-model",
                action_ref=digest(runtime.action.as_dict()),
                operator=runtime.operator,
            )
            physical = False
            copied_refused = True
            if kernel:
                review = coordinator.evaluate(
                    scope,
                    runtime.channels["child"],
                    lease.reference,
                    runtime.grant,
                    runtime.action,
                    idempotency_key="audit-review",
                )
                reserved = coordinator.reserve(
                    scope,
                    runtime.channels["child"],
                    lease.reference,
                    review.reference,
                    runtime.action,
                    idempotency_key="audit-reserve",
                )
                result = coordinator.guarded_dispatch(
                    scope, runtime.broker_channel, reserved.reference
                )
                original, (authorization, _) = next(iter(runtime.broker._results.items()))
                physical = (
                    result.status == "host_completed"
                    and original.physical_enforcement
                    and runtime.broker.verify_result(original, authorization)
                    and original.value == b"SYNTHETIC_OWNED_KERNEL_CANARY\n"
                )
                copied_refused = False
                try:
                    source.record_broker(runtime.broker, authorization, replace(original))
                except ValueError:
                    copied_refused = True
            else:
                enrolled = runtime.auth.require(runtime.channels["child"], role="workload")
                gate = SwarmGate(runtime.registry, AgentGate(runtime.core))
                gate.bind_audit(source, operator=runtime.operator)
                gate.evaluate_action(
                    enrolled.context,
                    runtime.action,
                    channel=enrolled.registry_channel,
                    adapter=enrolled.adapter,
                )
            flushed = source.flush(operator=runtime.operator, timeout=5)
            bundle = journal.export(operator=runtime.operator)
            checkpoint = journal.checkpoint(operator=runtime.operator)
            snapshot = source.snapshot(operator=runtime.operator)
            events = bundle["events"]
            risk = [row for row in events if row["kind"] == "risk_signal"]
            intent = [row for row in events if row["kind"] == "decision"]
            observed = [row for row in events if row["evidence"] == "observed"]
            encoded = json.dumps([bundle, snapshot], sort_keys=True)
            checks = {
                "original_capture_flushed": flushed,
                "chain_matches_explicit_checkpoint": verify_swarm_audit(bundle, checkpoint).valid,
                "model_diagnostic_only": bool(risk)
                and all(row["evidence"] == "diagnostic" for row in risk),
                "review_intent_only": bool(intent)
                and all(row["evidence"] == "intent" for row in intent),
                "raw_canary_and_path_absent": "SYNTHETIC_OWNED_KERNEL_CANARY" not in encoded
                and str(runtime.target) not in encoded,
                "tenant_refs_are_scoped": TenantRedactor(key, "different-tenant").ref(
                    "resource", str(runtime.target)
                )
                != journal.redactor.ref("resource", str(runtime.target)),
                "unsupported_parent_access_explicit": snapshot["unmediated_paths"] == "uncovered",
                "observations_require_original_kernel": bool(observed) == kernel
                and (not kernel or physical),
                "copied_broker_result_refused": copied_refused,
            }
            finding = outcome(
                "execute" if all(checks.values()) else "unknown",
                checks,
                backend="authenticated_kernel_completion" if physical else "not_forwarded",
                physical=physical,
                observations=int(physical),
                diagnostic_events=len(risk),
                intent_events=len(intent),
                observed_events=len(observed),
            )
            finding["model_inference"] = {
                "status": "synthetic_diagnostic",
                "evidence_authority": False,
            }
            return finding
        finally:
            if not source.close(operator=runtime.operator):
                raise ValueError("owned audit writer did not close")
