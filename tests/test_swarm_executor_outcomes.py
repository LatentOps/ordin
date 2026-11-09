"""Backend identity in public reports stays honest and never grants execution."""

import pytest

from ordin.swarm.linux_backend import ExecutorOutcome


def outcome(**values):
    return ExecutorOutcome(
        "unsupported",
        "broker.kernel_unavailable",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        False,
        None,
        0,
        0,
        None,
        **values,
    )


def test_existing_read_outcome_default_stays_compatible():
    assert outcome().as_dict()["backend"] == "linux-owned-file-read-v1"


@pytest.mark.parametrize("backend", ["linux-owned-tools-v1", "linux-confined-test-v1"])
def test_closed_owned_backend_report_keeps_its_actual_identity(backend):
    report = outcome(backend=backend).as_dict()
    assert report["backend"] == backend and report["execution_authority"] is False


def test_unknown_executor_identity_is_not_an_accepted_report():
    with pytest.raises(ValueError, match="report"):
        outcome(backend="caller-arbitrary-executor-v1").as_dict()
