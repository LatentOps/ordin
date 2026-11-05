"""Existing host sessions continue running while future routes are explicitly attached."""

from concurrent.futures import Future
from queue import Queue
import json
import socket
from threading import Event, Thread

import pytest

from ordin import ActionEnvelope
from ordin.swarm import (
    AttachCoverage,
    AttachedSession,
    HostSessionEndpoint,
    InMemoryAgentRegistry,
    RunningSessionIdentity,
    SwarmAttachManager,
    SwarmEvent,
    SwarmEventIngestor,
    SwarmGate,
    SwarmToolGateway,
)


class ExistingHost:
    def __init__(self, name):
        self.identity = RunningSessionIdentity(name, "session-" + name)
        self.connected = True
        self.router = None
        self.calls = []
        self.queue = Queue()
        self.thread = Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while True:
            item = self.queue.get()
            if item is None:
                return
            action, result = item
            try:
                if self.router is None:
                    value = self.execute(action)
                else:
                    value = self.router.call("shell", action, self.execute)
                result.set_result(value)
            except Exception as exc:
                result.set_exception(exc)

    def execute(self, action):
        self.calls.append(action)
        return "completed"

    def call(self, command):
        result = Future()
        self.queue.put((ActionEnvelope.shell(command), result))
        return result.result(timeout=5)

    def close(self):
        self.queue.put(None)
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


def fixture(*, timeout=30, max_sessions=256):
    now = [100.0]
    registry = InMemoryAgentRegistry(
        "tenant", "swarm", clock=lambda: now[0], heartbeat_timeout=timeout
    )
    events = SwarmEventIngestor(registry)
    gateway = SwarmToolGateway(events=events, clock=lambda: now[0])
    gate = SwarmGate(registry, events=events)
    manager = SwarmAttachManager(
        registry, events=events, gateway=gateway, gate=gate, max_sessions=max_sessions
    )
    return registry, events, gateway, manager, now


def endpoint(registry, host, mode="intercept", *, installer=True):
    adapter = object()
    channel = registry.bind_channel(adapter, runtime_id="existing-host")
    return HostSessionEndpoint(
        channel,
        adapter,
        identify=lambda: host.identity if host.connected else None,
        get_router=lambda: host.router,
        set_router=(lambda router: setattr(host, "router", router)) if installer else None,
        coverage=AttachCoverage(
            mode,
            frozenset({"shell", "mcp", "sdk"}),
            True,
            observed_pathways=frozenset({"hook", "mcp", "sdk"}),
        ),
    )


def test_running_two_agent_host_observation_and_mediation_without_restart():
    registry, _, _, manager, _ = fixture()
    hosts = [ExistingHost("a"), ExistingHost("b")]
    try:
        original_threads = [h.thread.ident for h in hosts]
        assert all(h.call("rm -rf /") == "completed" for h in hosts)
        observe = manager.register(endpoint(registry, hosts[0], "observe"))
        mediated = manager.register(endpoint(registry, hosts[1]))
        observation = manager.attach(observe)
        intercept = manager.attach(mediated)
        assert observation["pre_attach_history"] == intercept["pre_attach_history"] == "unknown"
        assert hosts[0].router is None  # Observation does not replace any executor.
        assert hosts[0].call("rm -rf /") == "completed"
        assert hosts[1].call("git status").value == "completed"
        blocked = hosts[1].call("rm -rf /")
        assert blocked.disposition == "deny" and blocked.ticket is None
        assert len(hosts[1].calls) == 2
        assert [h.thread.ident for h in hosts] == original_threads
        assert {v["pathway"] for v in intercept["pathways"]} == {
            "hook",
            "mcp",
            "sdk",
            "gateway",
            "outbound_network",
            "credential",
            "executor",
        }
    finally:
        for host in hosts:
            host.close()


def test_unwrapped_direct_socket_is_reported_uncovered_and_not_claimed_blocked():
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        handle = manager.register(endpoint(registry, host))
        report = manager.attach(handle)
        left, right = socket.socketpair()
        try:
            left.sendall(b"unwrapped")
            assert right.recv(32) == b"unwrapped"
        finally:
            left.close()
            right.close()
        network = next(v for v in report["pathways"] if v["pathway"] == "outbound_network")
        assert network["state"] == "uncovered" and network["coverage"] == "coverage_gap"
        assert not report["physical_enforcement"]
        assert "revoke_or_rotate_existing_credentials" in {v["plan"] for v in report["pathways"]}
    finally:
        host.close()


def test_attach_detach_are_idempotent_and_reattach_fences_original_context_and_router():
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        link = endpoint(registry, host)
        handle = manager.register(link)
        assert manager.register(link) is handle
        first = manager.attach(handle)
        old_context, _ = manager.context(handle)
        old_router = host.router
        assert manager.attach(handle) == first
        detached = manager.detach(handle)
        assert manager.detach(handle) == detached and host.router is None
        with pytest.raises(ValueError):
            old_router.call("shell", ActionEnvelope.shell("git status"), host.execute)
        second = manager.attach(handle)
        new_context, _ = manager.context(handle)
        assert new_context.identity.agent_id == old_context.identity.agent_id
        assert new_context.identity.session_id == old_context.identity.session_id
        assert second["generation"] > first["generation"]
        assert second["current_window"] == "unknown"
        with pytest.raises(ValueError):
            registry.authenticate(old_context, link.channel, link.adapter)
        with pytest.raises(ValueError):
            manager.status(AttachedSession(handle.binding_id))
        assert host.call("git status").value == "completed"
    finally:
        host.close()


def test_disconnect_replacement_and_route_loss_deny_future_calls_and_status_downgrades():
    for failure in ("disconnect", "replacement", "route"):
        registry, _, _, manager, _ = fixture()
        host = ExistingHost("a")
        try:
            handle = manager.register(endpoint(registry, host))
            manager.attach(handle)
            router = host.router
            if failure == "disconnect":
                host.connected = False
            elif failure == "replacement":
                host.identity = RunningSessionIdentity("a", "session-a")
            else:
                host.router = object()
            with pytest.raises(ValueError):
                router.call("shell", ActionEnvelope.shell("git status"), host.execute)
            report = manager.status(handle)
            assert report["state"] == "detached"
            assert all(v["coverage"] == "coverage_gap" for v in report["pathways"])
            assert not host.calls
        finally:
            host.close()


def test_enforce_missing_installer_and_failed_installer_refuse_without_false_coverage():
    for mode, installer in (("enforce", True), ("intercept", False)):
        registry, _, _, manager, _ = fixture()
        host = ExistingHost("a")
        try:
            handle = manager.register(endpoint(registry, host, mode, installer=installer))
            assert not manager.attach(handle, dry_run=True)["supported"]
            with pytest.raises(ValueError, match="restart"):
                manager.attach(handle)
            assert host.router is None and manager.status(handle)["generation"] == 0
        finally:
            host.close()
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        link = endpoint(registry, host)
        link.set_router = lambda value: None
        handle = manager.register(link)
        with pytest.raises(ValueError, match="attach failed"):
            manager.attach(handle)
        assert manager.status(handle)["state"] == "detached" and host.router is None
    finally:
        host.close()


def test_event_continuity_missing_history_disconnect_and_resume_are_explicit():
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        handle = manager.register(endpoint(registry, host, "observe"))
        manager.attach(handle)
        context, source = manager.context(handle)

        def event(sequence):
            return SwarmEvent(
                "e" + str(sequence),
                "message_sent",
                context.registry_id,
                context.identity,
                source.source_id,
                sequence,
                100,
                evidence_class="host_authenticated",
            )

        manager.ingest(handle, event(1))
        assert manager.status(handle)["current_window"] == "continuous_since_attach"
        manager.ingest(handle, event(3))
        assert manager.status(handle)["current_window"] == "unknown"
        manager.ingest(handle, event(2))
        assert manager.status(handle)["current_window"] == "unknown"
        manager.detach(handle)
        manager.attach(handle)
        with pytest.raises(ValueError):
            manager.ingest(handle, event(4))
        assert manager.status(handle)["pre_attach_history"] == "unknown"
    finally:
        host.close()


def test_dry_run_expiry_foreign_channel_and_registration_limits():
    registry, _, _, manager, now = fixture(max_sessions=1)
    host, other = ExistingHost("a"), ExistingHost("b")
    try:
        link = endpoint(registry, host)
        handle = manager.register(link)
        assert manager.attach(handle, dry_run=True)["dry_run"] and host.router is None
        assert manager.status(handle)["generation"] == 0
        with pytest.raises(ValueError, match="capacity"):
            manager.register(endpoint(registry, other))
        manager.attach(handle)
        now[0] += 31
        assert manager.status(handle)["state"] == "detached"
        foreign_registry, *_ = fixture()
        foreign = endpoint(foreign_registry, other)
        with pytest.raises(ValueError):
            manager.register(foreign)
    finally:
        host.close()
        other.close()


def test_revoked_gateway_facade_and_pending_ticket_cannot_execute():
    from tests.test_swarm_gateway import host as configured_gateway

    _, _, gateway, enroll, _ = configured_gateway()
    actor, _, _, _ = enroll("a")
    facade = gateway.review_gate(actor)
    authorization = gateway.prepare(actor, ActionEnvelope.shell("git status"))
    gateway.revoke_agent(actor)
    calls = []
    with pytest.raises(ValueError):
        gateway.forward(actor, authorization.ticket, lambda action: calls.append(action))
    with pytest.raises(ValueError, match="revoked"):
        facade.evaluate_action(ActionEnvelope.shell("git status"))
    assert not calls


def test_cli_dry_run_live_refusal_offline_status_and_doctor(tmp_path, capsys):
    from ordin.entrypoint import main
    from ordin.schema import validate_named_schema

    assert (
        main(["swarm", "attach", "--dry-run", "--mode", "intercept", "--route", "shell", "--json"])
        == 0
    )
    plan = json.loads(capsys.readouterr().out)
    assert not plan["supported"] and not plan["execution_authority"]
    assert validate_named_schema("swarm_attach_plan", plan) == []
    assert main(["swarm", "attach", "--json"]) == 2
    assert "authenticated host" in capsys.readouterr().out
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        handle = manager.register(endpoint(registry, host))
        report = manager.attach(handle)
        assert validate_named_schema("swarm_attach_status", report) == []
        path = tmp_path / "status.json"
        path.write_text(json.dumps(report))
        for command in ("status", "doctor"):
            assert main(["swarm", command, "--report", str(path), "--json"]) == 0
            output = json.loads(capsys.readouterr().out)
            assert output["report_source"] == "untrusted_file" and not output["verified_live"]
            assert validate_named_schema("swarm_attach_status", output) == []
        report["physical_enforcement"] = True
        path.write_text(json.dumps(report))
        assert main(["swarm", "status", "--report", str(path), "--json"]) == 2
        assert "invalid bounded" in capsys.readouterr().out
    finally:
        host.close()


def test_restart_required_routes_are_excluded_and_closed_channel_downgrades():
    registry, _, gateway, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        link = endpoint(registry, host)
        link.coverage = AttachCoverage(
            "intercept", frozenset({"shell", "mcp"}), restart_required=frozenset({"hook"})
        )
        handle = manager.register(link)
        report = manager.attach(handle)
        hook = next(v for v in report["pathways"] if v["pathway"] == "hook")
        assert hook["state"] == "restart_required" and hook["coverage"] == "coverage_gap"
        denied = host.call("git status")
        assert denied.disposition == "deny" and not host.calls
        registry.close_channel(link.channel, link.adapter)
        report = manager.status(handle)
        assert report["state"] == "detached" and host.router is None and not gateway._actors
    finally:
        host.close()


def test_pre_attach_events_cannot_retroactively_fill_history():
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    try:
        handle = manager.register(endpoint(registry, host, "observe"))
        manager.attach(handle)
        context, source = manager.context(handle)
        old = SwarmEvent(
            "old",
            "message_sent",
            context.registry_id,
            context.identity,
            source.source_id,
            1,
            99,
            evidence_class="host_authenticated",
        )
        with pytest.raises(ValueError, match="pre-attach"):
            manager.ingest(handle, old)
        assert manager.status(handle)["current_window"] == "unknown"
    finally:
        host.close()


def test_detach_waits_for_inflight_call_then_fences_future_calls():
    registry, _, _, manager, _ = fixture()
    host = ExistingHost("a")
    entered, release, detached = Event(), Event(), Event()
    worker = None
    try:
        handle = manager.register(endpoint(registry, host))
        manager.attach(handle)
        router = host.router

        def execute(action):
            entered.set()
            assert release.wait(5)
            return "completed"

        host.execute = execute
        result = Future()
        host.queue.put((ActionEnvelope.shell("git status"), result))
        assert entered.wait(5)

        def detach():
            manager.detach(handle)
            detached.set()

        worker = Thread(target=detach)
        worker.start()
        assert not detached.wait(0.05)
        release.set()
        assert result.result(timeout=5).value == "completed"
        assert detached.wait(5)
        with pytest.raises(ValueError):
            router.call("shell", ActionEnvelope.shell("git status"), execute)
    finally:
        release.set()
        if worker:
            worker.join(timeout=5)
        host.close()
