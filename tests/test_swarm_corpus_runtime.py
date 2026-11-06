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
