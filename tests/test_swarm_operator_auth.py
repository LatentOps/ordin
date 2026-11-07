"""Human RBAC uses real original TLS channels with roles separate from workloads."""

from contextlib import ExitStack
from copy import copy
from threading import Event, Thread
import ssl

import pytest

from ordin.swarm.operator_auth import HumanOperatorChannel, SwarmOperatorDirectory
from tests.test_swarm_broker import fixture
from tests.test_swarm_delegation import fingerprint, tls_pair


def enroll(data):
    auth, operator = data[1].authenticator, data[11]
    directory = SwarmOperatorDirectory(auth, operator=operator)
    alice = directory.enroll(
        principal_id="human-alice",
        certificate_digest=fingerprint("grandchild"),
        roles=("approve", "break_glass", "recover"),
        task_ids=("task",),
        operator=operator,
    )
    bob = directory.enroll(
        principal_id="human-bob",
        certificate_digest=fingerprint("sibling"),
        roles=("approve", "break_glass"),
        task_ids=("task",),
        operator=operator,
    )
    return directory, alice, bob


def test_actual_operator_credentials_have_finite_rbac_and_cannot_be_a_broker(tmp_path):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, alice, bob = enroll(data)
        for credential, person in (("grandchild", alice), ("sibling", bob)):
            server, _ = stack.enter_context(tls_pair(data[1].authenticator._tls, credential))
            channel = directory.authenticate(server)
            assert directory.require(channel, task_id="task", roles=("approve",)) is person
            for wrong in (
                copy(channel),
                HumanOperatorChannel(channel.channel_id),
                {"approved": True, "operator": person.principal_id},
            ):
                with pytest.raises(ValueError):
                    directory.require(wrong, task_id="task", roles=("approve",))
            with pytest.raises(ValueError):
                directory.require(channel, task_id="other-task", roles=("approve",))
            authority = directory._channels[channel][0]
            with pytest.raises(ValueError, match="wrong role"):
                data[1].authenticator.require(authority, role="broker")
        assert (
            alice.principal_id != bob.principal_id
            and alice.certificate_digest != bob.certificate_digest
        )


def test_workload_certificate_and_model_claim_cannot_self_enroll_or_authenticate_human(tmp_path):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, _, _ = enroll(data)
        with pytest.raises(ValueError, match="protected"):
            directory.enroll(
                principal_id="claimed-operator",
                certificate_digest=fingerprint("outsider"),
                roles=("approve",),
                task_ids=("task",),
                operator=object(),
            )
        with pytest.raises(ValueError, match="duplicate certificate"):
            directory.enroll(
                principal_id="workload-self",
                certificate_digest=fingerprint("child"),
                roles=("approve",),
                task_ids=("task",),
                operator=data[11],
            )
        server, _ = stack.enter_context(tls_pair(data[1].authenticator._tls, "child"))
        with pytest.raises(ValueError, match="wrong role"):
            directory.authenticate(server)
        with pytest.raises(ValueError):
            directory.authenticate({"certificate": fingerprint("grandchild"), "human": True})


def test_operator_expiry_revocation_and_tls_policy_change_fence_current_channel(tmp_path):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, alice, _ = enroll(data)
        server, _ = stack.enter_context(tls_pair(data[1].authenticator._tls, "grandchild"))
        channel = directory.authenticate(server)
        original = directory.binding_digest
        directory.revoke(alice.enrollment_id, operator=data[11])
        assert directory.binding_digest != original
        with pytest.raises(ValueError):
            directory.require(channel, task_id="task", roles=("approve",))
        with pytest.raises(ValueError):
            directory.member(alice.enrollment_id, task_id="task", roles=("approve",))
        data[1].authenticator._tls.verify_mode = ssl.CERT_NONE
        with pytest.raises(ValueError):
            directory.binding_digest


def test_duplicate_principal_and_wildcard_scope_cannot_satisfy_two_person_control(tmp_path):
    with fixture(tmp_path) as data:
        directory, _, _ = enroll(data)
        for principal, tasks in (("human-alice", ("task",)), ("another", ("*",))):
            with pytest.raises(ValueError):
                directory.enroll(
                    principal_id=principal,
                    certificate_digest=fingerprint("outsider"),
                    roles=("approve",),
                    task_ids=tasks,
                    operator=data[11],
                )


def test_urgent_operator_auth_does_not_wait_for_execution_barrier_or_sample_db_clock_under_locks(
    tmp_path,
):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, alice, _ = enroll(data)
        auth = data[1].authenticator
        server, _ = stack.enter_context(tls_pair(auth._tls, "grandchild"))
        original_clock = auth._clock

        def checked_db_clock():
            assert not auth._lock._is_owned()
            assert not directory._lock._is_owned()
            return original_clock()

        auth._clock = checked_db_clock
        holding, release, authorized = Event(), Event(), Event()

        def running_callback():
            with auth._registry._policy_execution_barrier:
                holding.set()
                release.wait(3)

        def authenticate():
            channel = directory.authenticate(server)
            assert directory.require(channel, task_id="task", roles=("approve",)) is alice
            authorized.set()

        callback = Thread(target=running_callback)
        callback.start()
        try:
            assert holding.wait(1)
            operator = Thread(target=authenticate)
            operator.start()
            assert authorized.wait(1), "urgent human control waited behind a running callback"
            operator.join(1)
            assert not operator.is_alive()
        finally:
            release.set()
            callback.join(1)


def test_overlapping_operator_clock_samples_can_complete_out_of_order(tmp_path):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, alice, _ = enroll(data)
        auth = data[1].authenticator
        first, _ = stack.enter_context(tls_pair(auth._tls, "grandchild"))
        second, _ = stack.enter_context(tls_pair(auth._tls, "grandchild"))
        sampled, release = Event(), Event()
        channels, failures = {}, []

        def clock():
            assert not auth._lock._is_owned()
            assert not directory._lock._is_owned()
            if not sampled.is_set():
                sampled.set()
                assert release.wait(2)
                return 100
            return 101

        auth._clock = clock

        def earlier():
            try:
                channels["earlier"] = auth.authenticate_operator(first)
            except Exception as error:
                failures.append(error)

        worker = Thread(target=earlier)
        worker.start()
        try:
            assert sampled.wait(1)
            channels["later"] = auth.authenticate_operator(second)
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive() and not failures
        assert channels["earlier"] is not channels["later"]
        for channel in channels.values():
            assert auth.require_operator(channel).enrollment_id == alice.enrollment_id
        assert auth._last_now == 101


def test_overlapping_old_operator_sample_cannot_revive_expired_channel(tmp_path):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, _, _ = enroll(data)
        auth = data[1].authenticator
        first, _ = stack.enter_context(tls_pair(auth._tls, "grandchild"))
        second, _ = stack.enter_context(tls_pair(auth._tls, "sibling"))
        channel = auth.authenticate_operator(first)
        sampled, release = Event(), Event()
        failures, accepted = [], []

        def clock():
            assert not auth._lock._is_owned()
            assert not directory._lock._is_owned()
            if not sampled.is_set():
                sampled.set()
                assert release.wait(2)
                return 101
            return 131

        auth._clock = clock

        def earlier():
            try:
                accepted.append(auth.require_operator(channel))
            except ValueError as error:
                failures.append(error)

        worker = Thread(target=earlier)
        worker.start()
        try:
            assert sampled.wait(1)
            auth.authenticate_operator(second)
        finally:
            release.set()
            worker.join(2)
        assert not worker.is_alive() and not accepted
        assert len(failures) == 1 and "expired" in str(failures[0])
        assert auth._last_now == 131


@pytest.mark.parametrize("sample", [99, float("nan"), float("inf"), -1, True])
def test_operator_clock_still_rejects_rollback_and_invalid_samples(tmp_path, sample):
    with fixture(tmp_path) as data, ExitStack() as stack:
        directory, _, _ = enroll(data)
        auth = data[1].authenticator
        socket, _ = stack.enter_context(tls_pair(auth._tls, "grandchild"))
        channel = auth.authenticate_operator(socket)
        auth._clock = lambda: sample
        with pytest.raises(ValueError):
            auth.require_operator(channel)
        with pytest.raises(ValueError):
            directory.authenticate(socket)
        assert auth._last_now == 100
