"""The packaged lab keeps original authority and backend facts correlated."""

from dataclasses import replace
import sys

import pytest

from ordin.swarm._corpus_runtime import CERTS, _fingerprint, owned_runtime


def test_packaged_runtime_has_distinct_original_workloads_and_leases(tmp_path):
    with owned_runtime(tmp_path / "lab", kernel=False) as runtime:
        assert runtime.names == ("parent", "child", "sibling")
        assert len({_fingerprint(name) for name in runtime.names}) == 3
        assert len(set(runtime.enrollments.values())) == 3
        coordinator, scope, control, child = runtime.coordinate()
        assert child.reference is not None
        assert set(runtime.leases) == set(runtime.names)
        assert runtime.broker is None and runtime.backend is None
        assert coordinator is not None and scope is not None and control is not None
    assert not (CERTS / "ca-key.pem").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="owned kernel backend requires Linux")
def test_packaged_runtime_correlates_original_kernel_result_and_rejects_replay(tmp_path):
    with owned_runtime(tmp_path / "lab") as runtime:
        prepared = runtime.broker.prepare(
            runtime.channels["child"], runtime.grant, runtime.action, idempotency_key="positive"
        )
        assert prepared.authorization is not None, prepared.reason_codes
        result = runtime.broker.dispatch(prepared.authorization)
        assert result.status == "completed"
        assert result.physical_enforcement
        assert result.value == b"SYNTHETIC_OWNED_KERNEL_CANARY\n"
        assert result.executor_outcome.observation is not None
        assert runtime.broker.verify_result(result, prepared.authorization)
        assert not runtime.broker.verify_result(replace(result), prepared.authorization)
        with pytest.raises(ValueError):
            runtime.broker.dispatch(prepared.authorization)


@pytest.mark.skipif(sys.platform != "linux", reason="owned kernel backend requires Linux")
def test_packaged_runtime_refuses_revoked_authority_before_backend(tmp_path):
    with owned_runtime(tmp_path / "lab") as runtime:
        prepared = runtime.broker.prepare(
            runtime.channels["child"], runtime.grant, runtime.action, idempotency_key="revoked"
        )
        assert prepared.authorization is not None
        runtime.service.operator_revoke(runtime.grant, operator=runtime.operator)
        result = runtime.broker.dispatch(prepared.authorization)
        assert not result.forwarded
        assert result.status != "completed"
        assert result.executor_outcome is None


def test_audit_intent_and_model_diagnostics_never_claim_backend_observation(tmp_path):
    from ordin.swarm.corpus_controls import run_control

    result = run_control("audit-intent-inference", agents=3, seed=276, workspace=tmp_path / "audit")
    assert result["actual"] == "execute" and all(result["checks"].values()), result
    assert result["facts"]["diagnostic_events"] == result["facts"]["intent_events"] == 1
    assert result["facts"]["observed_events"] == 0
    assert not result["backend_facts"]["physical_enforcement"]


@pytest.mark.skipif(sys.platform != "linux", reason="owned kernel backend requires Linux")
def test_audit_only_projects_original_owned_backend_evidence_as_observed(tmp_path):
    from ordin.swarm.corpus_kernel import run_kernel

    result = run_kernel("kernel-audit-provenance", workspace=tmp_path / "audit")
    assert result["actual"] == "execute" and all(result["checks"].values())
    assert result["facts"]["observed_events"] == 1
    assert result["backend_facts"]["authenticated_observations"] == 1
    assert result["backend_facts"]["physical_enforcement"]


@pytest.mark.skipif(sys.platform != "linux", reason="owned kernel backend requires Linux")
@pytest.mark.parametrize(
    "scenario",
    (
        "kernel-approval-warn",
        "kernel-approval-ask",
        "kernel-approval-replay",
        "kernel-approval-copy",
        "kernel-approval-mutation",
        "kernel-approval-block",
    ),
)
def test_human_tls_approval_keeps_original_job_and_core_constraints(tmp_path, scenario):
    from ordin.swarm.corpus_kernel import run_kernel

    result = run_kernel(scenario, workspace=tmp_path / "approval")
    assert all(result["checks"].values()), result
    assert result["actual"] == (
        "execute" if scenario in {"kernel-approval-warn", "kernel-approval-ask"} else "deny"
    )
    assert result["backend_facts"]["physical_enforcement"] == (
        scenario
        in {
            "kernel-approval-warn",
            "kernel-approval-ask",
            "kernel-approval-replay",
        }
    )
