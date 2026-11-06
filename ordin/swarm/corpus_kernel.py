"""Explicit owned-kernel subset. Unsupported hosts never receive a synthetic pass."""

from dataclasses import replace
from pathlib import Path
from time import perf_counter_ns

from ordin import ActionEnvelope
from ordin._runtime_json import digest

from ._corpus_runtime import owned_runtime
from .corpus_controls import outcome
from .linux_backend import ExecutorOutcome
from ._corpus_approval import APPROVAL_KERNEL_CASES

KERNEL_CASES = (
    "kernel-benign",
    "kernel-mutation",
    "kernel-swapped-tool",
    "kernel-replay",
    "kernel-revoked",
    "kernel-untrusted-outcome",
    "kernel-bypass",
    "kernel-audit-provenance",
    *APPROVAL_KERNEL_CASES,
)


def run_kernel(name: str, *, workspace: Path):
    if name not in KERNEL_CASES:
        raise ValueError("unknown owned kernel corpus case")
    if name in APPROVAL_KERNEL_CASES:
        from ._corpus_approval import run_approval_kernel

        workspace.mkdir(parents=True, exist_ok=False)
        return run_approval_kernel(name, workspace=workspace)
    if name == "kernel-audit-provenance":
        from ._corpus_audit import run_audit

        workspace.mkdir(parents=True, exist_ok=False)
        return run_audit(name, workspace=workspace)
    with owned_runtime(workspace, kernel=True) as runtime:
        prepared = runtime.broker.prepare(
            runtime.channels["child"], runtime.grant, runtime.action, idempotency_key=name
        )
        if prepared.authorization is None:
            return outcome(
                "unknown",
                {"required_kernel_available": False},
                backend="unsupported",
                unsupported_reason=list(prepared.reason_codes),
            )
        authorization = prepared.authorization
        selected = runtime.action
        if name == "kernel-mutation":
            selected = replace(
                selected,
                parameters={
                    **selected.parameters,
                    "arguments": {"path": str(runtime.target.parent / "outside.txt")},
                },
            )
        elif name == "kernel-swapped-tool":
            selected = replace(selected, parameters={**selected.parameters, "tool": "delete_file"})
        elif name == "kernel-revoked":
            runtime.service.operator_revoke(runtime.grant, operator=runtime.operator)
        elif name == "kernel-untrusted-outcome":
            scope = runtime.broker.authorization_scope(authorization)
            forged = ExecutorOutcome(
                "completed",
                "untrusted_fixture_claim",
                digest(scope.action.as_dict()),
                scope.plan.contract.digest,
                scope.plan.policy_digest,
                True,
                "a" * 64,
                0,
                0,
                None,
            )
            runtime.backend.execute = lambda *args, **kwargs: forged
        started = perf_counter_ns()
        result = runtime.broker.dispatch(authorization, action=selected)
        elapsed = perf_counter_ns() - started
        original = runtime.broker.verify_result(result, authorization)
        observed = bool(result.executor_outcome and result.executor_outcome.observation)
        if name in {"kernel-mutation", "kernel-swapped-tool", "kernel-revoked"}:
            return outcome(
                "deny" if not result.forwarded and result.status != "completed" else "execute",
                {
                    "refused_before_effect": not result.forwarded,
                    "original_result": original,
                    "no_observed_completion": not observed,
                },
                backend="not_forwarded",
                authorization_status=result.status,
                **({"revocation_ns": elapsed} if name == "kernel-revoked" else {}),
            )
        if name == "kernel-untrusted-outcome":
            return outcome(
                "unknown",
                {
                    "untrusted_not_completed": result.status == "unknown",
                    "no_physical_claim": not result.physical_enforcement,
                    "conservative_hold": result.budget_status == "uncertain",
                    "no_trusted_observation": not observed,
                },
                backend="unknown",
            )
        verified = (
            result.status == "completed" and result.physical_enforcement and observed and original
        )
        if name == "kernel-replay":
            refused = False
            try:
                runtime.broker.dispatch(authorization)
            except ValueError:
                refused = True
            return outcome(
                "deny" if refused else "execute",
                {"first_actual_completion": bool(verified), "replay_refused": refused},
                backend="authenticated_kernel_completion",
                physical=bool(verified),
                observations=int(observed),
            )
        if name == "kernel-bypass":
            rejected = runtime.broker.prepare(
                runtime.channels["child"],
                runtime.grant,
                ActionEnvelope.shell("rm -rf /fixture-owned/canaries"),
                idempotency_key="mediated-denial",
            )
            raw = runtime.target.read_bytes()
            return outcome(
                "uncovered",
                {
                    "actual_owned_kernel_read": bool(verified),
                    "mediated_unsafe_request_refused": rejected.authorization is None,
                    "raw_parent_access_remains_uncovered": raw
                    == b"SYNTHETIC_OWNED_KERNEL_CANARY\n",
                },
                backend="authenticated_kernel_and_unmediated_parent_read",
                physical=bool(verified),
                observations=int(observed),
                coverage="owned_child_only",
            )
        return outcome(
            "execute" if verified else "unknown",
            {
                "actual_kernel_completion": bool(verified),
                "expected_canary": result.value == b"SYNTHETIC_OWNED_KERNEL_CANARY\n",
            },
            backend="authenticated_kernel_completion" if verified else "unknown",
            physical=bool(verified),
            observations=int(observed),
        )
