"""Exact managed writes, durable CAS history, and closed syscall authority."""

from dataclasses import replace
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from threading import RLock

import pytest

from ordin import ToolCallAdapter
from ordin.action import ActionEnvelope
from ordin._runtime_json import digest
from ordin.runtime_contract import (
    CredentialBinding,
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    PrivilegeCapability,
    RuntimeCapabilityContract,
    ToolCapability,
)
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin.swarm._owned_protocol import filter_code
from ordin.swarm._owned_state import OwnedFileState
from ordin.swarm.owned_tools import LinuxOwnedToolsBackend, OwnedHTTPRoute, _parse_write
from tests.swarm_owned_tools_samples import configured
from tests.test_swarm_broker import require_kernel
from tests.test_swarm_broker import fixture as broker_fixture
from tests.test_swarm_delegation import fingerprint, tls_pair


def write_requirements(
    path="/owned/report.txt", content="bounded UTF-8: π", *, version=0, expected=None
):
    """Explicit protected-owner test action, not a model approval or core review."""
    action = ToolCallAdapter("ordin-owned").adapt(
        "write_artifact",
        {
            "path": path,
            "content": content,
            "expected_version": version,
            "expected_digest": expected,
        },
        action_id="operator-fixture-write",
    )
    contract = RuntimeCapabilityContract(
        action.action_id,
        digest(action.as_dict()),
        "allow",
        "low",
        filesystem=(FilesystemCapability("write", path, "exact"),),
        tools=(ToolCapability("ordin-owned", None, "write_artifact"),),
        process=ProcessCapability(execution=False, spawn_children=False),
        privilege=PrivilegeCapability(escalation=False),
        source={
            "kind": "tool",
            "adapter": "owned_operator_fixture",
            "operation": "call",
            "effects": ["filesystem.write"],
            "provenance_digest": None,
        },
    )
    return action, contract


def parse(action, contract, maximum=64):
    return _parse_write(
        action,
        contract,
        paths=("/owned/report.txt",),
        runtime="ordin-owned",
        tool="write_artifact",
        maximum=maximum,
        uid=1000,
    )


def test_write_parser_binds_utf8_content_destination_version_and_complete_authority():
    action, contract = write_requirements()
    assert parse(action, contract) == ("/owned/report.txt", "bounded UTF-8: π".encode(), 0, None)
    with pytest.raises(ValueError, match="UTF-8"):
        parse(*write_requirements(content="π" * 33))
    for arguments in (
        {**action.parameters["arguments"], "path": "/owned/../report.txt"},
        {**action.parameters["arguments"], "expected_digest": "a" * 64},
        {**action.parameters["arguments"], "expected_version": True},
        {**action.parameters["arguments"], "expected_version": 1},
        {**action.parameters["arguments"], "overwrite": True},
    ):
        changed = replace(action, parameters={**action.parameters, "arguments": arguments})
        with pytest.raises(ValueError):
            parse(
                changed, replace(contract, contract_id="", action_digest=digest(changed.as_dict()))
            )
    for changed in (
        replace(contract, contract_id="", network=(NetworkCapability("example.com", 443),)),
        replace(
            contract,
            contract_id="",
            filesystem=contract.filesystem + (FilesystemCapability("read", "/elsewhere", "exact"),),
        ),
        replace(contract, contract_id="", process=ProcessCapability(execution=True)),
        replace(contract, contract_id="", privilege=PrivilegeCapability(escalation=True)),
    ):
        with pytest.raises(ValueError, match="capability"):
            parse(action, changed)


def test_content_bound_is_checked_before_action_hashing(monkeypatch):
    action, contract = write_requirements(content="x" * 65)
    monkeypatch.setattr(
        "ordin.swarm.owned_tools.digest", lambda value: pytest.fail("oversized action hashed")
    )
    with pytest.raises(ValueError, match="bound"):
        parse(action, contract)


def run_filter(mode, number, *args, arch=0xC000003E):
    """Tiny classic-BPF evaluator: an independent check of actual numeric profile."""
    data = {0: number, 4: arch, **{16 + n * 8: value & 0xFFFFFFFF for n, value in enumerate(args)}}
    pc, accumulator = 0, 0
    code = filter_code(mode)
    for _ in range(512):
        operation, yes, no, value = code[pc]
        pc += 1
        if operation == 0x20:
            accumulator = data.get(value, 0)
        elif operation == 0x15:
            pc += yes if accumulator == value else no
        elif operation == 0x06:
            return value
        else:
            raise AssertionError("unexpected BPF instruction")
    raise AssertionError("profile did not terminate")


def test_closed_filter_allows_only_managed_directory_atomic_operations():
    allow, deny = 0x7FFF0000, 0x00050001
    for number in (41, 42, 57, 59, 85, 86, 87, 165, 262, 322, 437):
        assert run_filter("write", number) == deny
    assert run_filter("write", 1, 1) == allow
    assert run_filter("write", 1, 1, arch=0x40000003) == 0x80000000
    for flags in (2752512, 655554):
        assert run_filter("write", 257, 3, 0, flags, 0o600) == allow
        assert run_filter("write", 257, 4, 0, flags, 0o600) == deny
        assert run_filter("write", 257, 3, 0, flags, 0o666) == deny
    assert run_filter("write", 257, 3, 0, 577, 0o600) == deny  # No truncating open.
    for flags in (1, 2):
        assert run_filter("write", 316, 3, 0, 3, 0, flags) == allow
        assert run_filter("write", 316, 3, 0, 4, 0, flags) == deny
    assert run_filter("write", 316, 3, 0, 3, 0, 0) == deny
    assert run_filter("write", 263, 3, 0, 0) == allow
    assert run_filter("write", 263, 3, 0, 512) == deny
    assert run_filter("write", 77, 1, 100) == allow
    assert run_filter("write", 77, 3, 100) == deny
    assert run_filter("http", 257, 3, 0, 2752512, 0o600) == deny
    for syscall in (44, 45, 48, 51, 52, 54, 55):
        assert run_filter("http", syscall, 3) == allow
        assert run_filter("http", syscall, 4) == deny
    assert run_filter("http", 16, 3, 0x5421) == allow
    assert run_filter("write", 16, 3, 0x5421) == deny
    for descriptor in (0, 1, 2, 4, 255, 0xFFFFFFFF):
        assert run_filter("http", 16, descriptor, 0x5421) == deny
    for command in (0, 0x541B, 0x5451, 0xFFFFFFFF):
        assert run_filter("http", 16, 3, command) == deny
    for number in (41, 42, 53, 72):
        assert run_filter("http", number, 3, 3) == deny


@pytest.mark.skipif(os.name != "posix", reason="private POSIX flock ownership")
def test_durable_history_keeps_unresolved_intents_and_cas_across_restart(tmp_path):
    tmp_path.chmod(0o700)
    initial = {
        "report.txt": {"version": 0, "content_digest": None, "identity": None, "pending": None}
    }
    path = tmp_path / "state.sqlite3"
    state = OwnedFileState(path, "a" * 64, initial, initialize=True)
    old = state.record("report.txt")
    try:
        with pytest.raises((OSError, ValueError)):
            OwnedFileState(path, "a" * 64, initial, initialize=False)
        state.begin(
            "report.txt", old, nonce="b" * 64, action_digest="c" * 64, content_digest="d" * 64
        )
        with pytest.raises(ValueError, match="unresolved"):
            state.record("report.txt")
    finally:
        state.close()
    state = OwnedFileState(path, "a" * 64, initial, initialize=False)
    try:
        with pytest.raises(ValueError, match="unresolved"):
            state.record("report.txt")
        with pytest.raises(ValueError, match="original"):
            state.finish(
                "report.txt", "e" * 64, identity=None, content_digest=None, completed=False
            )
        assert (
            state.finish(
                "report.txt", "b" * 64, identity=None, content_digest=None, completed=False
            )
            == old
        )
        state.begin(
            "report.txt", old, nonce="f" * 64, action_digest="c" * 64, content_digest="d" * 64
        )
        result = state.finish(
            "report.txt", "f" * 64, identity={"inode": 123}, content_digest="d" * 64, completed=True
        )
        assert result["version"] == 1
        with pytest.raises(ValueError, match="CAS"):
            state.begin(
                "report.txt", old, nonce="f" * 64, action_digest="c" * 64, content_digest="d" * 64
            )
    finally:
        state.close()
    with pytest.raises(FileExistsError):
        OwnedFileState(path, "a" * 64, initial, initialize=True)
    with pytest.raises(ValueError, match="identity"):
        OwnedFileState(path, "e" * 64, initial, initialize=False)


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://example.com/a?x=1"},
        {"url": "https://example.com/a#fragment"},
        {"addresses": ("127.0.0.1",)},
        {"addresses": ("169.254.169.254",), "allow_private": True},
        {"addresses": ("93.184.216.34", "93.184.216.34")},
        {"headers": (("X-Mode", "one"), ("x-mode", "two"))},
        {"headers": (("Authorization", "Bearer public"),)},
        {"headers": (("X-Mode", "one\r\nInjected: true"),)},
        {"headers": (("Host", "other.example"),)},
        {"max_response_bytes": 65537},
    ],
)
def test_http_route_configuration_fails_closed_without_opening_network(changes):
    with pytest.raises(ValueError):
        OwnedHTTPRoute(
            **(
                {
                    "route_id": "docs",
                    "url": "https://example.com/a",
                    "addresses": ("93.184.216.34",),
                }
                | changes
            )
        )


def test_original_credential_receipt_is_reused_and_never_reminted_or_copied(tmp_path):
    # Cache-only unit test; this uninstalled object never executes or claims
    # kernel enforcement. Sources/profile are genuine enrolled fixture objects.
    backend = LinuxOwnedToolsBackend.__new__(LinuxOwnedToolsBackend)
    backend.http_routes = (
        OwnedHTTPRoute(
            "private-docs",
            "https://example.com/a",
            ("93.184.216.34",),
            credential_binding=CredentialBinding("fixture-api", "example.com", 443),
            credential=b"private-fixture-token",
        ),
    )
    backend._lock, backend._limit, backend._credential_reviews = RLock(), 1, {}
    action = ActionEnvelope(
        "network",
        "http.request",
        backend.http_routes[0].public_parameters(),
        action_id="credential-get",
    )
    with broker_fixture(tmp_path) as values:
        broker, service, *_ = values
        sources = [
            row.source
            for row in service.authenticator._enrollments.values()
            if row.role == "workload"
        ]
        source, foreign = sources
        receipts = backend.credential_uses(source, action, service.issuer.profile)
        assert backend.credential_uses(source, action, service.issuer.profile) is receipts
        assert backend.verify_credential_uses(source, action, service.issuer.profile, receipts)
        assert not backend.verify_credential_uses(
            source, action, service.issuer.profile, (copy.copy(receipts[0]),)
        )
        assert not backend.verify_credential_uses(foreign, action, service.issuer.profile, receipts)
        with pytest.raises(ValueError, match="capacity"):
            backend.credential_uses(
                source, replace(action, action_id="other-get"), service.issuer.profile
            )
        next(iter(backend._credential_reviews.values())).used = True
        with pytest.raises(ValueError, match="consumed"):
            backend.credential_uses(source, action, service.issuer.profile)
        assert len(backend._credential_reviews) == 1
        assert "private-fixture-token" not in repr(backend.http_routes[0]) + json.dumps(
            action.as_dict()
        )


def test_broker_channel_renewal_requires_same_original_tls_enrollment(tmp_path):
    with broker_fixture(tmp_path) as values:
        broker, service, *_ = values
        clock, operator = values[10], values[11]
        auth = service.authenticator
        old = broker._broker_channel
        original = auth.require(old, role="broker")
        clock[0] += 31
        with pytest.raises(ValueError):
            auth.require(old, role="broker")
        fresh = auth.authenticate(auth._channels[old].socket)
        generation = service.issuer._generation
        broker.refresh_broker_channel(fresh, operator=operator)
        assert broker._broker_channel is fresh and auth.require(fresh, role="broker") is original
        assert service.issuer._generation == generation
        with pytest.raises(ValueError):
            broker.refresh_broker_channel(copy.copy(fresh), operator=operator)
        with pytest.raises(ValueError):
            broker.refresh_broker_channel(fresh, operator=object())
        auth.enroll_broker(
            host_id="host-a", certificate_digest=fingerprint("broker-a"), operator=operator
        )
        with tls_pair(auth._tls, "broker-a") as (server, _):
            other = auth.authenticate(server)
            with pytest.raises(ValueError, match="original"):
                broker.refresh_broker_channel(other, operator=operator)
        assert broker._broker_channel is fresh


def test_real_broker_read_preserved_and_write_never_autoapproves(tmp_path):
    with configured(tmp_path) as data:
        prepared = data.broker.prepare(
            data.channel, data.grant, data.read_action, idempotency_key="owned-read"
        )
        assert prepared.disposition == "execute", prepared.as_dict()
        result = data.broker.dispatch(prepared.authorization)
        assert result.status == "completed", result.as_dict()
        assert data.broker.verify_result(result, prepared.authorization)
        before = data.target.read_bytes()
        action = data.write_action()
        review = data.details["core"].review_action(action)
        assert review.decision == "warn" and review.risk == "medium"
        denied = data.broker.prepare(
            data.channel, data.grant, action, idempotency_key="owned-write"
        )
        assert denied.disposition != "execute", denied.as_dict()
        assert data.target.read_bytes() == before


def operator_backend(tmp_path, *, http_routes=()):
    """Only caller-owned new fixture paths are chowned; never existing user paths."""
    require_kernel()
    tmp_path.chmod(0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    uid, gid = LinuxOwnedToolsBackend.worker_identity()
    if os.geteuid() == 0:
        os.chown(workspace, uid, gid)
    operator = object()
    install = tempfile.TemporaryDirectory(prefix="ordin-owned-write-test-")
    backend = LinuxOwnedToolsBackend(
        workspace,
        ("report.txt",),
        Path(install.name),
        operator=operator,
        initialize=True,
        http_routes=http_routes,
    )
    return backend, operator, workspace / "report.txt", install


def test_actual_atomic_write_receipt_cas_staleness_and_changed_contents(tmp_path, monkeypatch):
    backend, operator, target, install = operator_backend(tmp_path)
    try:
        action, contract = write_requirements(str(target))
        compiled = backend.compile_action(action, contract)
        assert compiled.enforceable, compiled.as_dict()
        plan = compiled.plan
        assert backend.compile_action(action, contract).plan is plan  # Use-time budget recheck.
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-write-test", "b" * 64)
        result = backend.execute(plan, action, source, operator=operator)
        assert result.status == "completed", result.as_dict()
        assert backend.verify_outcome(result, plan) and result.physical_enforcement
        assert target.read_bytes() == action.parameters["arguments"]["content"].encode()
        metadata = json.loads(result.value)
        assert (
            metadata["version"] == 1
            and metadata["content_digest"] == hashlib.sha256(target.read_bytes()).hexdigest()
        )
        evidence = backend.evidence_record(result, operator=operator)
        assert evidence["filesystem_scope"] == "managed_directory" and all(
            evidence["checks"].values()
        )
        assert not backend.validate(plan).ok
        assert not backend.compile_action(action, contract).enforceable
        snapshot = backend.snapshot(str(target), operator=operator)
        next_action, next_contract = write_requirements(
            str(target), "second write", version=1, expected=snapshot["content_digest"]
        )
        next_plan = backend.compile_action(next_action, next_contract).plan
        assert next_plan is not None
        replaced = backend.execute(next_plan, next_action, source, operator=operator)
        assert replaced.status == "completed", replaced.as_dict()
        assert backend.snapshot(str(target), operator=operator)["version"] == 2
        assert target.read_bytes() == b"second write"
        third_action, third_contract = write_requirements(
            str(target),
            "third write",
            version=2,
            expected=hashlib.sha256(b"second write").hexdigest(),
        )
        third_plan = backend.compile_action(third_action, third_contract).plan
        target.write_bytes(b"outside owned route")
        monkeypatch.setattr(
            "subprocess.Popen",
            lambda *args, **kwargs: pytest.fail("changed inode/content forwarded"),
        )
        refused = backend.execute(third_plan, third_action, source, operator=operator)
        assert refused.status != "completed" and not refused.physical_enforcement
        assert target.read_bytes() == b"outside owned route"
    finally:
        backend.close()
        install.cleanup()


def test_actual_write_version_history_survives_new_backend_without_reinitialization(tmp_path):
    backend, operator, target, install = operator_backend(tmp_path)
    try:
        action, contract = write_requirements(str(target))
        plan = backend.compile_action(action, contract).plan
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-write-test", "b" * 64)
        result = backend.execute(plan, action, source, operator=operator)
        assert result.status == "completed", result.as_dict()
        before = backend.snapshot(str(target), operator=operator)
    finally:
        backend.close()
        install.cleanup()
    with tempfile.TemporaryDirectory(prefix="ordin-owned-reattach-") as fresh_install:
        attached = LinuxOwnedToolsBackend(
            target.parent, (target.name,), Path(fresh_install), operator=operator
        )
        try:
            assert attached.snapshot(str(target), operator=operator) == before
            assert not attached.compile_action(
                action, contract
            ).enforceable  # Old create-only action.
        finally:
            attached.close()


def test_real_write_original_job_stop_and_changed_or_symlink_target_refuse(tmp_path, monkeypatch):
    backend, operator, target, install = operator_backend(tmp_path)
    try:
        action, contract = write_requirements(str(target), "never forwarded")
        plan = backend.compile_action(action, contract).plan
        assert plan is not None
        source = RuntimeEvidenceSource(backend.name, "a" * 64, "owned-write-test", "b" * 64)
        job = backend.create_job(plan, operator=operator)
        assert backend.request_stop(job, operator=operator) == "canceled"
        monkeypatch.setattr(
            "subprocess.Popen", lambda *args, **kwargs: pytest.fail("stopped effect forwarded")
        )
        with pytest.raises(ValueError, match="consumed"):
            backend.execute(plan, action, source, operator=operator, job=job)
        assert not target.exists()
        target.symlink_to(tmp_path / "outside.txt")
        refused = backend.execute(plan, action, source, operator=operator)
        assert refused.status != "completed" and not refused.physical_enforcement
        assert not (tmp_path / "outside.txt").exists()
    finally:
        backend.close()
        install.cleanup()
