"""Terminal aggregate labels never replace original lower process custody."""

import pytest
from ordin._runtime_json import digest
from ordin.enforcement_backend import EnforcementPlan
from ordin.swarm.confined_tests import LinuxConfinedTestRunner
from ordin.swarm.linux_backend import ExecutorOutcome, KernelJob
from ordin.swarm._owned_test_output import TEST_PROTOCOL
from tests.test_swarm_managed_process import lifecycle_fixture
from tests.test_swarm_owned_stop import retained_backend


def retained_runner(tmp_path, *, terminal=None):
    engine, lower_job, operator, lower_row = lifecycle_fixture(tmp_path)
    process = lower_row.process
    if terminal is None:
        process.refuse_stop = True
        assert engine.request_stop(lower_job, operator=operator) == "unknown"
    else:
        process.returncode = 0 if terminal == "exited" else -9
        if terminal == "canceled":
            lower_row.cancel.set()
            lower_row.stop_reason = "canceled"
    native = engine.finish(lower_job, operator=operator)
    runner = LinuxConfinedTestRunner.__new__(LinuxConfinedTestRunner)
    runner._operator, runner._engine = operator, engine
    backend, _, old_plan, job, row = retained_backend()
    backend._operator = operator
    backend._test_runner = runner
    backend._test_jobs[job] = lower_job
    plan = EnforcementPlan(backend.name, old_plan.contract, {"profile": TEST_PROTOCOL})
    row.binding = (plan.plan_id, plan.contract.action_digest, plan.contract.digest)
    lower_plan = EnforcementPlan(runner.name, plan.contract, {})
    backend._test_plans[plan.plan_id] = (plan, lower_plan, None)
    lower_plan = backend._test_plans[plan.plan_id][1]
    status = "completed" if native.status == "exited" else native.status
    lower = ExecutorOutcome(
        status,
        "tests.owned_stop_fixture",
        plan.contract.action_digest,
        plan.contract.digest,
        lower_plan.policy_digest,
        False,
        None,
        0,
        0,
        None,
        backend=runner.name,
    )
    runner._outcomes = {lower: (lower_plan, digest(lower.as_dict()), {})}
    upper = backend._result(plan, status, "broker.owned_test_stop_fixture", job=job)
    backend._test_outcomes[upper] = (lower,)
    return backend, operator, plan, job, row, runner, lower_job, native, lower, upper


def test_finished_upper_unknown_always_retries_original_lower_stop(tmp_path):
    backend, operator, plan, job, row, runner, lower_job, native, lower, upper = retained_runner(
        tmp_path
    )
    engine_row = runner._engine._jobs[lower_job]
    process = engine_row.process
    original_kills = process.kills
    original = upper.as_dict(), lower.as_dict(), native.as_dict()
    assert row.state == "finished" and process.poll() is None
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert process.kills == original_kills + 1 and process.poll() is None
    process.refuse_stop = False
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert process.poll() == -9
    assert backend.request_stop(job, operator=operator) == "unknown"
    assert row.outcome is upper and runner._engine.finish(lower_job, operator=operator) is native
    assert original == (upper.as_dict(), lower.as_dict(), native.as_dict())
    assert backend.verify_outcome(upper, plan) and runner.verify_outcome(
        lower, backend._test_plans[plan.plan_id][1]
    )
    runner.close(operator=operator)


@pytest.mark.parametrize("terminal,expected", [("exited", "completed"), ("canceled", "canceled")])
def test_retained_terminal_test_jobs_still_consult_lower_proof_idempotently(
    tmp_path, terminal, expected
):
    backend, operator, plan, job, row, runner, lower_job, native, lower, upper = retained_runner(
        tmp_path, terminal=terminal
    )
    process = runner._engine._jobs[lower_job].process
    waits = process.waits
    with pytest.raises(ValueError):
        backend.request_stop(KernelJob(job.job_id), operator=operator)
    with pytest.raises(ValueError):
        backend.request_stop(job, operator=object())
    assert backend.request_stop(job, operator=operator) == expected
    assert process.waits == waits + 1
    assert backend.request_stop(job, operator=operator) == expected
    assert process.waits == waits + 2 and process.kills == 0
    assert row.outcome is upper and runner._engine.finish(lower_job, operator=operator) is native
    assert backend.verify_outcome(upper, plan)
    runner.close(operator=operator)
