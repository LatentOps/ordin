"""Original SQLite phase exclusion and preemptive custody; not native qualification.

The unguarded control reproduces the conflicting metadata overlap, not the
Linux timeout duration. The guarded control must exclude it and finish bounded.
"""

from contextlib import ExitStack
import os
from threading import Event, RLock, Thread
from types import SimpleNamespace

import pytest

pytest.importorskip("ordin_swarm")

from ordin.swarm.coordinator_store import CoordinatorClock, SQLiteCoordinatorStore
from ordin_swarm.host_authority import HostAuthority, _HostCleanupIncomplete
from ordin_swarm.host_runtime import HostClient, ManagedToolHost, _Client
from ordin_swarm.host_service import ManagedHostServer


def original_authority(tmp_path, *, now=None):
    authority = object.__new__(HostAuthority)
    authority._close_lock, authority._control_lock = RLock(), RLock()
    authority._closing = authority._cleanup_complete = False
    authority.operator = object()
    source_time = [100] if now is None else now
    store = SQLiteCoordinatorStore(
        tmp_path / "coordinator.sqlite", create=True, clock=lambda: source_time[0]
    )
    authority.clock = CoordinatorClock(store)
    authority.profile = SimpleNamespace(require_unchanged=lambda: None)
    authority.expires_at = 600
    authority.contexts = {}
    authority.owner = {"policy_digest": "a" * 64, "owner_fence": 1}
    authority.scope, authority.control, authority.root_socket = object(), object(), object()
    authority.root_grant = "original-root"
    authority.auth = SimpleNamespace(
        authenticate=lambda socket: "original-channel", fence=lambda **kwargs: None
    )
    authority.stack = ExitStack()
    return authority, store


def managed_host(authority):
    host = object.__new__(ManagedToolHost)
    host._authority, host._operator = authority, authority.operator
    host._lock, host._close_lock = RLock(), RLock()
    host._closed = host._cleanup_complete = False
    host._clients, host._approvals = {}, {}
    host.shutdown_requested = Event()
    host._lock_fd = None
    return host


@pytest.mark.parametrize("guarded", [False, True])
def test_real_sqlite_maintenance_and_factory_clock_phase_interleaving(tmp_path, guarded):
    authority, store = original_authority(tmp_path)
    writer_entered, release_writer = Event(), Event()
    factory_attempted, factory_entered = Event(), Event()
    completed, errors, samples = [], [], []
    authority.refresh_broker_channel = lambda: None

    def bind(*args):
        with store.transaction():
            writer_entered.set()
            assert release_writer.wait(2), "bounded writer phase was not released"
        completed.append("committed")

    authority.coordinator = SimpleNamespace(
        heartbeat=lambda *args, **kwargs: authority.owner,
        admit=lambda *args: SimpleNamespace(reference="original-lease"),
        bind_grant=bind,
    )

    def verify(proof, *, policy_digest):
        assert proof is authority.factory_proof and policy_digest == "a" * 64
        factory_entered.set()
        samples.append(authority.clock())
        return True

    authority.factory_proof = object()
    authority.broker = SimpleNamespace(
        verify_activation=verify, describe_activation=lambda proof: {"expires_at": 600}
    )

    def writer():
        try:
            if guarded:
                authority.maintenance()
            else:
                HostAuthority.maintenance.__wrapped__(authority)
        except BaseException as error:
            errors.append(error)

    def factory():
        factory_attempted.set()
        try:
            if guarded:
                authority.refresh_factory()
            else:
                HostAuthority.refresh_factory.__wrapped__(authority)
            completed.append("validated")
        except BaseException as error:
            errors.append(error)

    writers, readers = Thread(target=writer), Thread(target=factory)
    writers.start()
    assert writer_entered.wait(2)
    readers.start()
    try:
        assert factory_attempted.wait(1)
        overlapped = factory_entered.wait(0.1)
    finally:
        release_writer.set()
        writers.join(timeout=3)
        readers.join(timeout=3)
    assert not writers.is_alive() and not readers.is_alive() and errors == []
    # The same phase-exclusion assertion is RED in the original unguarded body.
    assert overlapped is (not guarded)
    assert sorted(completed) == ["committed", "validated"] and samples == [100]
    assert authority.expires_at == 600


def test_busy_periodic_maintenance_cannot_sample_or_extend_authority(tmp_path):
    authority, _ = original_authority(tmp_path)
    host = managed_host(authority)
    entered, release = Event(), Event()
    calls = []
    authority.maintenance = lambda: calls.append("renewed")
    authority.coordinator = SimpleNamespace(
        checkpoint=lambda *args, **kwargs: calls.append("checkpoint")
    )

    def busy():
        with authority.control_phase():
            entered.set()
            assert release.wait(2)

    thread = Thread(target=busy)
    thread.start()
    try:
        assert entered.wait(1)
        host.maintenance()
        assert calls == [] and authority.expires_at == 600
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_authentication_waits_for_phase_then_uses_fresh_original_clock(tmp_path):
    now = [100]
    authority, _ = original_authority(tmp_path, now=now)
    host = managed_host(authority)
    host.profile = SimpleNamespace(require_unchanged=lambda: None)
    observed = []

    def authenticate(connection):
        value = authority.clock()
        observed.append(value)
        if value >= 150:
            raise ValueError("original channel expired")
        return "channel"

    authority.auth.authenticate = authenticate
    client = HostClient("original")
    host._clients[client] = _Client(SimpleNamespace(fileno=lambda: 1), "actor", "channel")
    attempted, finished = Event(), Event()
    errors = []

    def request():
        attempted.set()
        try:
            host.require_client(client)
        except ValueError as error:
            errors.append(str(error))
        finally:
            finished.set()

    with authority.control_phase():
        thread = Thread(target=request)
        thread.start()
        assert attempted.wait(1)
        assert not finished.wait(0.05) and observed == []
        assert host._lock.acquire(blocking=False), "row lock remained held over phase wait"
        host._lock.release()
        now[0] = 200
    thread.join(timeout=2)
    assert not thread.is_alive() and observed == [200] and errors == ["original channel expired"]


def test_preemptive_stop_retains_storage_tls_and_lock_until_original_phase_leaves(tmp_path):
    authority, _ = original_authority(tmp_path)
    host = managed_host(authority)
    host._lock_fd = os.open(tmp_path / "host.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    descriptor = host._lock_fd
    entered, release, stopped = Event(), Event(), Event()
    released, effects, stops = [], [], []
    unknown = {"status": "unknown", "held": 8}
    job = object()

    def request_stop(original):
        assert original is job
        stops.append(original)
        stopped.set()

    authority.broker = SimpleNamespace(
        _state_lock=RLock(), _pending={job: unknown}, request_stop=request_stop
    )
    authority.backend = SimpleNamespace(close=lambda: released.append("storage"))
    authority.stack.callback(lambda: released.append("tls"))

    def effect():
        with authority.control_phase():
            effects.append("original-effect")
            entered.set()
            assert release.wait(2)

    thread = Thread(target=effect)
    thread.start()
    try:
        assert entered.wait(1)
        with pytest.raises(ValueError):
            host.request_shutdown(operator=object())
        host.request_shutdown(operator=authority.operator)
        assert stopped.wait(0.1) and host._closed and host.shutdown_requested.is_set()
        with pytest.raises(_HostCleanupIncomplete) as failure:
            host.close()
        assert released == [] and unknown == {"status": "unknown", "held": 8}
        os.fstat(descriptor)
        with pytest.raises(ValueError):
            host.require_client(HostClient("new"))
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()
    failure.value.retry_cleanup()
    assert released == ["storage", "tls"] and effects == ["original-effect"]
    assert host._lock_fd is None and unknown == {"status": "unknown", "held": 8}
    assert stops and all(value is job for value in stops)


def test_server_stop_watcher_uses_original_capability_while_rpc_phase_busy(tmp_path):
    authority, _ = original_authority(tmp_path)
    host = managed_host(authority)
    stopped, entered, release, accept_entered = Event(), Event(), Event(), Event()
    original = object()
    authority.broker = SimpleNamespace(
        _state_lock=RLock(),
        _pending={original: object()},
        request_stop=lambda job: stopped.set() if job is original else pytest.fail("foreign stop"),
    )
    authority.backend = SimpleNamespace(close=lambda: None)
    server = object.__new__(ManagedHostServer)
    server.host, server._operator = host, authority.operator
    server._lock, server._close_lock = RLock(), RLock()
    server._cleanup_complete, server._threads, server._sockets = False, set(), set()

    class Listener:
        def accept(self):
            accept_entered.set()
            host.shutdown_requested.wait(0.1)
            raise TimeoutError

        def close(self):
            pass

    server.listener = Listener()

    def busy():
        with authority.control_phase():
            entered.set()
            assert release.wait(3)

    busy_thread = Thread(target=busy)
    failures = []

    def run():
        try:
            server.run()
        except _HostCleanupIncomplete as error:
            failures.append(error)

    runner = Thread(target=run)
    busy_thread.start()
    assert entered.wait(1)
    runner.start()
    try:
        assert accept_entered.wait(1)
        host.shutdown_requested.set()  # Same event as original CLI signal path.
        assert stopped.wait(0.5)
        runner.join(timeout=1)
        assert not runner.is_alive() and failures
    finally:
        release.set()
        busy_thread.join(timeout=2)
        runner.join(timeout=2)
    failures[0].retry_cleanup()
    assert server._cleanup_complete and host._cleanup_complete
