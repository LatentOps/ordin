"""Real local mutual TLS plus original issuer, full request and credential controls."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct

import pytest

from ordin import ActionEnvelope, AgentGate, Ordin
from ordin.assurance import (
    AssuranceGate,
    DelegationAuthority,
    DelegationIssuer,
    HostEvidenceSource,
    RestSemantics,
)
from ordin.assurance.rest import derive_rest_request_contract
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import CredentialBinding, FilesystemCapability, NetworkCapability
from ordin.runtime_requests_v2 import derive_runtime_request_contract_v2
from ordin.swarm import InMemoryAgentRegistry
from ordin.swarm.credential_broker import SwarmCredentialBroker
from ordin.swarm.delegation import SwarmDelegationService
from ordin.swarm.workload_auth import AuthorityChannel, WorkloadAuthenticator
from tests.assurance.test_delegation import maximum, child_max
from tests.assurance.test_delegating_gate import action
from tests.assurance.test_invariants import SEMANTICS
from tests.assurance.test_profiles import REPO, POLICY_HASH, approve, selected, config_profile


CERTS = Path(__file__).parent / "fixtures/swarm_tls"


def fingerprint(name):
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((CERTS / (name + ".pem")).read_text())
    ).hexdigest()


def server_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(CERTS / "ca.pem"))
    context.load_cert_chain(str(CERTS / "server.pem"), str(CERTS / "server-key.pem"))
    return context


@contextmanager
def tls_pair(context, name):
    left, right = socket.socketpair()
    left.settimeout(5)
    right.settimeout(5)
    client_context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(CERTS / "ca.pem")
    )
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.load_cert_chain(str(CERTS / (name + ".pem")), str(CERTS / (name + "-key.pem")))
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(context.wrap_socket, left, server_side=True)
        client = client_context.wrap_socket(right, server_hostname="localhost")
        server = pending.result(timeout=5)
    try:
        yield server, client
    finally:
        server.close()
        client.close()


GET = ActionEnvelope(
    "network",
    "http.request",
    {"url": "https://fixture.invalid/docs", "method": "GET"},
    action_id="get",
)


@contextmanager
def configured(
    tmp_path, *, credential=False, admission_lifetime=10, selected_core=None, request_action=None
):
    profile = approve(selected(tmp_path, config_profile()))
    parent = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    clock = [100]
    core = Ordin(rest_semantics=RestSemantics()) if credential else Ordin(tool_semantics=SEMANTICS)
    if selected_core is not None:
        core = selected_core
    authority = maximum()
    if credential:
        contract = derive_rest_request_contract(core.review_action(GET))
        authority = DelegationAuthority(
            RuntimeCapabilityBoundary(
                "credential-root",
                network=contract.capability.network,
                credentials=(CredentialBinding("fixture-key", "fixture.invalid", 443),),
            ),
            rest_requests=(contract.request,),
        )
    elif request_action is not None:
        request_contract = derive_runtime_request_contract_v2(core.review_action(request_action))
        cap = request_contract.capability
        assert not cap.unknowns
        authority = DelegationAuthority(
            RuntimeCapabilityBoundary(
                "request-root",
                filesystem=cap.filesystem,
                network=cap.network,
                tools=cap.tools,
                process=cap.process,
                privilege=cap.privilege,
                credentials=cap.credentials,
            ),
            request_contract.requests,
        )
    issuer = DelegationIssuer(parent, profile, authority, authority, clock=lambda: clock[0])
    root = issuer.authorize_root(authority, grant_id="root", expires_at=200)
    registry = InMemoryAgentRegistry("tenant", "swarm", clock=lambda: clock[0])
    tls = server_context()
    operator = object()
    auth = WorkloadAuthenticator(registry, tls, operator=operator, clock=lambda: clock[0])
    service = SwarmDelegationService(
        issuer,
        AssuranceGate(AgentGate(core), profile),
        auth,
        operator=operator,
        admission_lifetime=admission_lifetime,
    )
    enrollments, channels, sources, contexts, registry_channels, adapters, sockets = (
        {},
        {},
        {},
        {},
        {},
        {},
        {},
    )
    with ExitStack() as stack:
        for name in ("parent", "child", "sibling", "grandchild"):
            source = (
                parent
                if name == "parent"
                else replace(
                    parent, principal=name, session_digest=hashlib.sha256(name.encode()).hexdigest()
                )
            )
            adapter = object()
            registry_channel = registry.bind_channel(adapter, runtime_id="fixture-" + name)
            context = registry.enroll(
                registry_channel,
                adapter,
                agent_id=name,
                session_id="session-" + name,
                task_id="task",
            )
            host = "host-a" if name == "parent" else "host-b"
            enrollment = auth.enroll_workload(
                host_id=host,
                certificate_digest=fingerprint(name),
                context=context,
                source=source,
                channel=registry_channel,
                adapter=adapter,
                operator=operator,
            )
            server, client = stack.enter_context(tls_pair(tls, name))
            enrollments[name], channels[name], sources[name], contexts[name] = (
                enrollment,
                auth.authenticate(server),
                source,
                context,
            )
            registry_channels[name], adapters[name], sockets[name] = (
                registry_channel,
                adapter,
                (server, client),
            )
        for name, host in (("broker-a", "host-a"), ("broker-b", "host-b")):
            enrollments[name] = auth.enroll_broker(
                host_id=host, certificate_digest=fingerprint(name), operator=operator
            )
            server, client = stack.enter_context(tls_pair(tls, name))
            channels[name], sockets[name] = auth.authenticate(server), (server, client)
        root_ref = service.publish_root(enrollments["parent"], root, operator=operator)
        yield (
            service,
            auth,
            issuer,
            root_ref,
            enrollments,
            channels,
            sources,
            contexts,
            registry,
            registry_channels,
            adapters,
            clock,
            operator,
            authority,
            sockets,
        )


def issue(data, target="child", *, parent=None, rights=None, request_id=None):
    service, _, _, root, enrollments, channels, *_ = data
    return service.issue_child(
        channels["parent"] if parent is None else channels[parent[0]],
        root.grant_id if parent is None else parent[1],
        enrollments[target],
        rights or child_max(),
        request_id=request_id or target,
        lifetime=30,
    )


def test_real_mutual_tls_cross_host_subset_and_exact_one_use_dispatch(tmp_path):
    with configured(tmp_path) as data:
        service, auth, issuer, root, enrollments, channels, *_ = data
        grant = issue(data)
        current = service.require_current(channels["child"], grant.grant_id)
        assert current.authority_digest == child_max().digest
        review = service.review(channels["child"], grant.grant_id, action())
        assert review.disposition == "execute" and review.admission_id
        calls = []
        result = service.guarded_dispatch(
            channels["broker-b"],
            review.admission_id,
            action(),
            lambda proposed: calls.append(proposed.as_dict()) or "ok",
        )
        assert result.status == "host_completed" and result.value == "ok" and len(calls) == 1
        with pytest.raises(ValueError, match="consumed"):
            service.guarded_dispatch(
                channels["broker-b"],
                review.admission_id,
                action(),
                lambda proposed: calls.append(proposed),
            )
        assert review.as_dict()["execution_authority"] is False
        assert current.as_dict()["requires_online_authority"]


def test_tls_certificate_dict_foreign_context_and_unenrolled_peer_cannot_authenticate(tmp_path):
    with configured(tmp_path) as data:
        _, auth, _, root, _, channels, _, _, _, _, _, _, _, _, sockets = data
        with pytest.raises(ValueError):
            auth.authenticate({"verified": True, "certificate": fingerprint("child")})
        with pytest.raises(ValueError):
            auth.require(AuthorityChannel(channels["child"].channel_id), role="workload")
        with tls_pair(auth._tls, "outsider") as (server, client):
            with pytest.raises(ValueError, match="not enrolled"):
                auth.authenticate(server)
        with tls_pair(server_context(), "child") as (server, client):
            with pytest.raises(ValueError, match="original verified"):
                auth.authenticate(server)
        auth.close(channels["child"])
        with pytest.raises(ValueError):
            auth.require(channels["child"], role="workload")


def test_child_cannot_broaden_rights_impersonate_sibling_or_use_wrong_host(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, root, _, channels, *_ = data
        broadened = replace(
            child_max(),
            capability=replace(
                child_max().capability,
                filesystem=(FilesystemCapability("write", "/fixture/.env", "exact"),),
            ),
        )
        with pytest.raises(ValueError):
            issue(data, rights=broadened)
        child = issue(data)
        with pytest.raises(ValueError, match="owned"):
            service.require_current(channels["sibling"], child.grant_id)
        with pytest.raises(ValueError):
            service.require_current(channels["child"], "f" * 64)
        review = service.review(channels["child"], child.grant_id, action())
        calls = []
        with pytest.raises(ValueError, match="refused"):
            service.guarded_dispatch(
                channels["broker-a"], review.admission_id, action(), lambda a: calls.append(a)
            )
        assert not calls


def test_parent_revocation_fences_descendants_and_unused_admissions(tmp_path):
    with configured(tmp_path) as data:
        service, _, issuer, root, _, channels, *_ = data
        child = issue(data)
        grandchild = issue(data, "grandchild", parent=("child", child.grant_id), rights=child_max())
        review = service.review(channels["grandchild"], grandchild.grant_id, action())
        affected = service.revoke(channels["parent"], root.grant_id, child.grant_id)
        assert len(affected) == 2
        with pytest.raises(ValueError):
            service.require_current(channels["grandchild"], grandchild.grant_id)
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"],
                review.admission_id,
                action(),
                lambda a: pytest.fail("revoked forward"),
            )


def test_sibling_revocation_preserves_other_grant_but_fences_stale_review(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, root, _, channels, *_ = data
        child, sibling = issue(data), issue(data, "sibling")
        stale = service.review(channels["sibling"], sibling.grant_id, action("stale"))
        with pytest.raises(ValueError):
            service.revoke(channels["child"], child.grant_id, sibling.grant_id)
        service.revoke(channels["parent"], root.grant_id, child.grant_id)
        assert service.require_current(channels["sibling"], sibling.grant_id)
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], stale.admission_id, action("stale"), lambda a: None
            )
        fresh = service.review(channels["sibling"], sibling.grant_id, action("fresh"))
        assert (
            service.guarded_dispatch(
                channels["broker-b"], fresh.admission_id, action("fresh"), lambda a: "ok"
            ).status
            == "host_completed"
        )


@pytest.mark.parametrize("mutation", ["expiry", "partition", "epoch", "policy", "action"])
def test_unused_admission_cannot_survive_changed_current_state(tmp_path, mutation):
    with configured(tmp_path) as data:
        service, _, _, _, _, channels, _, _, registry, _, _, clock, operator, *_ = data
        child = issue(data)
        review = service.review(channels["child"], child.grant_id, action())
        proposed = action()
        if mutation == "expiry":
            clock[0] += 11
        elif mutation == "partition":
            service.set_available(False, operator=operator)
            with pytest.raises(ValueError, match="unavailable"):
                service.require_current(channels["child"], child.grant_id)
            service.set_available(True, operator=operator)
        elif mutation == "epoch":
            registry.advance_policy_epoch(1)
        elif mutation == "policy":
            service.fence_policy(operator=operator)
        else:
            proposed = action(path="/fixture/.env")
        calls = []
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], review.admission_id, proposed, lambda a: calls.append(a)
            )
        assert not calls


def test_duplicate_issuance_is_idempotent_conflicts_and_concurrent_broadening_refuse(tmp_path):
    with configured(tmp_path) as data:
        service, _, issuer, _, _, _, *_ = data
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: issue(data, request_id="same-request"), range(8)))
        assert len({v.grant_id for v in results}) == 1 and len(issuer._issued) == 2
        with pytest.raises(ValueError, match="conflicting"):
            issue(data, request_id="same-request", rights=maximum())


def test_unknown_database_operation_cannot_become_empty_authority(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, _, _, channels, *_ = data
        child = issue(data)
        proposed = ActionEnvelope(
            "database",
            "delete",
            {"table": "records", "filter": {"id": 1}, "principal": "parent", "approved": True},
            action_id="delete",
        )
        review = service.review(channels["child"], child.grant_id, proposed)
        assert review.disposition != "execute" and review.admission_id is None
        assert (
            service.review(channels["child"], child.grant_id, action("after")).disposition
            == "execute"
        )


def test_callback_failure_is_consumed_and_public_audit_omits_private_errors(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, _, _, channels, *_ = data
        child = issue(data)
        review = service.review(channels["child"], child.grant_id, action())
        calls = []

        def forward(a):
            calls.append(a)
            raise OSError("private destination credential")

        result = service.guarded_dispatch(
            channels["broker-b"], review.admission_id, action(), forward
        )
        assert result.status == "unknown" and len(calls) == 1
        with pytest.raises(ValueError):
            service.guarded_dispatch(channels["broker-b"], review.admission_id, action(), forward)
        assert "private destination credential" not in json.dumps(service.audit())


def test_real_tls_authority_protocol_preserves_current_scope(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, root, _, channels, _, _, _, _, _, _, _, _, sockets = data
        server, client = sockets["parent"]
        body = json.dumps({"operation": "current", "grant_id": root.grant_id}).encode()
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(service.serve_one, server)
            client.sendall(struct.pack("!I", len(body)) + body)
            (size,) = struct.unpack("!I", client.recv(4))
            response = bytearray()
            while len(response) < size:
                response.extend(client.recv(size - len(response)))
            pending.result(timeout=5)
        packet = json.loads(response)
        assert packet["grant_id"] == root.grant_id and packet["requires_online_authority"]
        assert not packet["execution_authority"]
        with pytest.raises(ValueError):
            service.handle_request(
                channels["parent"],
                {"operation": "current", "grant_id": root.grant_id, "principal": "child"},
            )


def test_exact_rest_credentials_stay_private_and_require_separate_credential_right(tmp_path):
    from ordin.swarm.credential_broker import SwarmCredentialBroker

    with configured(tmp_path, credential=True) as data:
        service, _, _, _, _, channels, _, _, _, _, _, _, operator, maximum_rights, _ = data
        child = issue(data, rights=maximum_rights)
        broker = SwarmCredentialBroker(service, operator=operator)
        secret = b"SYNTHETIC_PRIVATE_CREDENTIAL_VALUE"
        calls = []
        route = broker.register(
            binding=CredentialBinding("fixture-key", "fixture.invalid", 443),
            action=GET,
            credential=secret,
            forward=lambda request: calls.append(request) or secret,
            operator=operator,
        )
        reviewed = broker.prepare(channels["child"], child.grant_id, route, GET)
        assert reviewed.disposition == "execute" and reviewed.admission_id
        result = broker.dispatch(channels["broker-b"], reviewed.admission_id, GET)
        assert result.status == "host_completed" and result.value is None
        assert calls[0].credential == secret
        assert secret.decode() not in repr(calls[0]) + json.dumps(broker.audit()) + json.dumps(
            service.audit()
        ) + json.dumps(result.as_dict())
        for params in (
            {**GET.parameters, "url": "https://other.invalid/docs"},
            {**GET.parameters, "url": "http://fixture.invalid/docs"},
            {**GET.parameters, "method": "POST"},
            {**GET.parameters, "headers": {"X-Mode": "changed"}},
            {**GET.parameters, "body": {"changed": True}},
        ):
            with pytest.raises(ValueError):
                broker.prepare(
                    channels["child"],
                    child.grant_id,
                    route,
                    replace(GET, action_id="changed", parameters=params),
                )
        no_credential = replace(
            maximum_rights, capability=replace(maximum_rights.capability, credentials=())
        )
        sibling = issue(data, "sibling", rights=no_credential)
        denied = broker.prepare(
            channels["sibling"],
            sibling.grant_id,
            route,
            replace(GET, action_id="no-credential-right"),
        )
        assert denied.disposition != "execute" and denied.admission_id is None


@pytest.mark.parametrize("kind", ["registry_parent", "certificate_parent", "registry_child"])
def test_workload_revocation_invalidates_current_descendant_authority(tmp_path, kind):
    with configured(tmp_path) as data:
        (
            service,
            auth,
            _,
            _,
            enrollments,
            channels,
            _,
            contexts,
            registry,
            rchannels,
            adapters,
            _,
            operator,
            *_,
        ) = data
        child = issue(data)
        pending = service.review(channels["child"], child.grant_id, action())
        if kind == "certificate_parent":
            auth.revoke_enrollment(enrollments["parent"], operator=operator)
        else:
            who = "parent" if kind == "registry_parent" else "child"
            registry.end(contexts[who], rchannels[who], adapters[who])
        with pytest.raises(ValueError):
            service.require_current(channels["child"], child.grant_id)
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"],
                pending.admission_id,
                action(),
                lambda a: pytest.fail("stale workload executed"),
            )


def test_tls_configuration_weakening_and_foreign_tenant_task_are_refused(tmp_path):
    with configured(tmp_path) as data:
        _, auth, _, _, _, channels, sources, _, registry, _, _, _, operator, *_ = data
        auth._tls.verify_mode = ssl.CERT_NONE
        with pytest.raises(ValueError):
            auth.require(channels["child"], role="workload")
        auth._tls.verify_mode = ssl.CERT_REQUIRED
        adapter = object()
        channel = registry.bind_channel(adapter, runtime_id="other-task")
        context = registry.enroll(
            channel, adapter, agent_id="other", session_id="other", task_id="other-task"
        )
        with pytest.raises(ValueError, match="task"):
            auth.enroll_workload(
                host_id="host-b",
                certificate_digest=fingerprint("outsider"),
                context=context,
                source=replace(sources["child"], principal="other"),
                channel=channel,
                adapter=adapter,
                operator=operator,
            )
        other = InMemoryAgentRegistry("foreign", "swarm", clock=lambda: 100)
        foreign_adapter = object()
        foreign_channel = other.bind_channel(foreign_adapter, runtime_id="foreign")
        foreign_context = other.enroll(
            foreign_channel,
            foreign_adapter,
            agent_id="foreign",
            session_id="foreign",
            task_id="task",
        )
        with pytest.raises(ValueError):
            auth.enroll_workload(
                host_id="host-b",
                certificate_digest=fingerprint("outsider"),
                context=foreign_context,
                source=replace(sources["child"], principal="foreign"),
                channel=foreign_channel,
                adapter=foreign_adapter,
                operator=operator,
            )


def test_rest_optional_extension_preserves_legacy_digest_and_all_maxima(tmp_path):
    from ordin.assurance._json import digest as authority_digest
    from ordin.assurance import verify_delegation_subset

    legacy = maximum()
    packet = legacy.as_dict()
    assert set(packet) == {"capability", "requests", "network_grants", "requires_approval"}
    assert authority_digest("delegation_authority", packet) == legacy.digest
    assert DelegationAuthority.from_dict({**packet, "rest_requests": []}).as_dict() == packet
    with configured(tmp_path, credential=True) as data:
        rights = data[13]
        assert DelegationAuthority.from_dict(rights.as_dict()) == rights
        changed = replace(
            rights, rest_requests=(replace(rights.rest_requests[0], commitment="f" * 64),)
        )
        assert not verify_delegation_subset(changed, rights, rights, rights).ok
        for slot in range(3):
            maxima = [rights, rights, rights]
            maxima[slot] = replace(rights, rest_requests=())
            assert not verify_delegation_subset(rights, *maxima).ok
        outside = replace(
            rights,
            capability=replace(
                rights.capability,
                network=(replace(rights.capability.network[0], paths=("/other",)),),
            ),
        )
        assert not verify_delegation_subset(outside, rights, rights, rights).ok


@pytest.mark.parametrize("protocol", ["json-rpc", "graphql", "mcp"])
def test_remote_exact_protocol_authority_preserves_arguments_and_identity(tmp_path, protocol):
    from ordin import MCPAdapter, ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry
    from ordin.policy import ReviewPolicy
    from ordin.runtime_requirements import RuntimeRequirementProfile

    if protocol == "json-rpc":
        proposed = ActionEnvelope(
            "network",
            "jsonrpc.request",
            {
                "url": "https://fixture.invalid/rpc",
                "body": {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"id": "a"}},
            },
            action_id="rpc",
        )
        changed = replace(
            proposed,
            action_id="changed",
            parameters={
                **proposed.parameters,
                "body": {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"id": "b"}},
            },
        )
        core = Ordin(policy=ReviewPolicy("block"))
    elif protocol == "graphql":
        proposed = ActionEnvelope(
            "network",
            "graphql.request",
            {
                "url": "https://fixture.invalid/graphql",
                "query": "query Q($id:ID!) { user(id:$id) { name } }",
                "variables": {"id": "a"},
            },
            action_id="query",
        )
        changed = replace(
            proposed,
            action_id="changed",
            parameters={**proposed.parameters, "variables": {"id": "b"}},
        )
        core = Ordin(policy=ReviewPolicy("block"))
    else:
        semantics = ToolSemanticsRegistry(
            "fixture-mcp",
            "1",
            (
                ToolSemanticRule(
                    "read",
                    "mcp",
                    "read_file",
                    ("filesystem.read",),
                    server="fixture",
                    resources=(ToolResourceBinding("path", "path"),),
                ),
            ),
        )
        requirements = RuntimeRequirementProfile(
            "fixture-mcp",
            client_executables=("/fixture/bin/mcp-client",),
            spawn_children=False,
            mcp_endpoints={"fixture": "https://fixture.invalid/mcp"},
            mcp_versions={"fixture": ("2025-11-25",)},
        )
        core = Ordin(tool_semantics=semantics, runtime_requirements=requirements)
        proposed = MCPAdapter("fixture").adapt(
            "read_file", {"path": "/fixture/source"}, action_id="read"
        )
        changed = MCPAdapter("fixture").adapt(
            "read_file", {"path": "/fixture/other"}, action_id="changed"
        )
    with configured(tmp_path, selected_core=core, request_action=proposed) as data:
        service, _, _, _, _, channels, *_ = data
        child = issue(data, rights=data[13])
        allowed = service.review(channels["child"], child.grant_id, proposed)
        assert (
            service._grants[child.grant_id]
            .gate.preview_action(replace(proposed, action_id="preview-allowed"))
            .verification.ok
        )
        if protocol == "json-rpc":
            # Unknown RPC effects keep the existing core warning/approval gate.
            assert allowed.disposition == "escalate" and allowed.admission_id is None
        else:
            assert allowed.disposition == "execute" and allowed.admission_id
            assert (
                service.guarded_dispatch(
                    channels["broker-b"], allowed.admission_id, proposed, lambda a: None
                ).status
                == "host_completed"
            )
        denied = service.review(channels["child"], child.grant_id, changed)
        assert denied.disposition != "execute" and denied.admission_id is None
        assert (
            not service._grants[child.grant_id]
            .gate.preview_action(replace(changed, action_id="preview-denied"))
            .verification.ok
        )


def test_credential_revocation_and_parent_revocation_never_inject_unused_secret(tmp_path):
    from ordin.swarm.credential_broker import SwarmCredentialBroker

    with configured(tmp_path, credential=True) as data:
        service, _, _, root, _, channels, _, _, _, _, _, _, operator, rights, _ = data
        child = issue(data, rights=rights)
        calls = []
        broker = SwarmCredentialBroker(service, operator=operator)
        route = broker.register(
            binding=CredentialBinding("fixture-key", "fixture.invalid", 443),
            action=GET,
            credential=b"PRIVATE",
            forward=lambda a: calls.append(a),
            operator=operator,
        )
        pending = broker.prepare(channels["child"], child.grant_id, route, GET)
        service.operator_revoke(root.grant_id, operator=operator)
        with pytest.raises(ValueError):
            broker.dispatch(channels["broker-b"], pending.admission_id, GET)
        assert not calls


def test_authority_frame_limits_and_duplicate_json_close_the_channel(tmp_path):
    with configured(tmp_path) as data:
        service, _, _, root, _, channels, _, _, _, _, _, _, _, _, sockets = data
        server, client = sockets["parent"]
        malformed = (
            b'{"operation":"current","operation":"review","grant_id":"'
            + root.grant_id.encode()
            + b'"}'
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(service.serve_one, server)
            client.sendall(struct.pack("!I", len(malformed)) + malformed)
            with pytest.raises(ValueError, match="transport"):
                pending.result(timeout=5)
        assert server.fileno() == -1


def test_expired_admissions_release_core_pending_quota_without_refunding_commits(tmp_path):
    with configured(tmp_path) as data:
        service, _, issuer, _, _, channels, _, _, _, _, _, clock, *_ = data
        child = issue(data)
        pending = service.review(channels["child"], child.grant_id, action("unused"))
        assert len(issuer._pending) == 1
        clock[0] += 11
        fresh = service.review(channels["child"], child.grant_id, action("fresh"))
        assert len(issuer._pending) == 1 and fresh.admission_id
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], pending.admission_id, action("unused"), lambda a: None
            )
        result = service.guarded_dispatch(
            channels["broker-b"], fresh.admission_id, action("fresh"), lambda a: None
        )
        assert result.status == "host_completed" and sum(issuer._used.values()) == 1
        assert not service.cancel(channels["child"], fresh.admission_id)


def test_concurrent_remote_commit_consumes_exactly_once_and_cancel_requires_owner(tmp_path):
    with configured(tmp_path) as data:
        service, _, issuer, _, _, channels, *_ = data
        child = issue(data)
        pending = service.review(channels["child"], child.grant_id, action("concurrent"))
        calls = []
        assert not service.cancel(channels["sibling"], pending.admission_id)

        def forward(_):
            try:
                return service.guarded_dispatch(
                    channels["broker-b"],
                    pending.admission_id,
                    action("concurrent"),
                    lambda a: calls.append(a),
                ).status
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(forward, range(8)))
        assert (
            results.count("host_completed") == 1
            and len(calls) == 1
            and sum(issuer._used.values()) == 1
        )
        canceled = service.review(channels["child"], child.grant_id, action("canceled"))
        assert service.cancel(channels["child"], canceled.admission_id)
        with pytest.raises(ValueError):
            service.guarded_dispatch(
                channels["broker-b"], canceled.admission_id, action("canceled"), lambda a: None
            )


def test_rest_request_commitment_does_not_turn_broad_tcp_into_protocol_authority():
    from ordin.assurance.rest import RestRequestBoundary, verify_rest_request_authority

    contract = derive_rest_request_contract(
        Ordin(rest_semantics=RestSemantics()).review_action(GET)
    )
    tcp = RuntimeCapabilityBoundary(
        "tcp", network=(NetworkCapability("fixture.invalid", 443, "tcp", "write"),)
    )
    result = verify_rest_request_authority(contract, RestRequestBoundary(tcp, (contract.request,)))
    assert not result.ok and result.result == "exceeds_boundary"
    changed = replace(
        contract.capability,
        network=(replace(contract.capability.network[0], host="other.invalid"),),
        contract_id="",
    )
    with pytest.raises(ValueError, match="differs"):
        derive_rest_request_contract(
            Ordin(rest_semantics=RestSemantics()).review_action(GET), capability=changed
        )


def test_revoke_credential_route_cancels_unused_issuer_ticket(tmp_path):
    with configured(tmp_path, credential=True) as data:
        service, _, issuer, _, _, channels, _, _, _, _, _, _, operator, rights, _ = data
        child = issue(data, rights=rights)
        broker = SwarmCredentialBroker(service, operator=operator)
        calls = []
        route = broker.register(
            binding=CredentialBinding("fixture-key", "fixture.invalid", 443),
            action=GET,
            credential=b"SYNTHETIC_SECRET",
            forward=lambda request: calls.append(request),
            operator=operator,
        )
        pending = broker.prepare(channels["child"], child.grant_id, route, GET)
        assert len(issuer._pending) == 1
        broker.revoke(route, operator=operator)
        assert not issuer._pending
        with pytest.raises(ValueError):
            broker.dispatch(channels["broker-b"], pending.admission_id, GET)
        assert not calls


def test_live_remote_reports_and_wire_data_have_closed_schema_contracts(tmp_path):
    from ordin.schema import validate_named_schema

    with configured(tmp_path) as data:
        service, _, _, _, _, channels, *_ = data
        child = issue(data)
        pending = service.review(channels["child"], child.grant_id, action())
        scope = service.admission_scope(channels["broker-b"], pending.admission_id)
        result = service.guarded_dispatch(
            channels["broker-b"], pending.admission_id, action(), lambda a: None
        )
        for name, payload in (
            ("swarm_remote_delegation", child.as_dict()),
            ("swarm_remote_delegation", child.to_wire()),
            ("swarm_remote_review", pending.as_dict()),
            ("swarm_remote_review", pending.to_wire()),
            ("swarm_broker_admission_scope", scope.as_dict()),
            ("swarm_broker_admission_scope", scope.to_wire()),
            ("swarm_delegation_dispatch", result.as_dict()),
        ):
            assert validate_named_schema(name, payload) == []
        assert child.grant_id not in json.dumps(child.as_dict()) + json.dumps(service.audit())
        assert pending.admission_id not in json.dumps(pending.as_dict()) + json.dumps(
            service.audit()
        )
        for payload in service.audit():
            assert validate_named_schema("swarm_authority_audit", payload) == []


def test_credential_registration_refuses_secret_in_action_context_or_binding_name(tmp_path):
    with configured(tmp_path, credential=True) as data:
        service = data[0]
        operator = data[12]
        broker = SwarmCredentialBroker(service, operator=operator)
        secret = b"SYNTHETIC_PRIVATE_VALUE"
        for proposed, binding in (
            (
                replace(GET, parameters={**GET.parameters, "headers": {"X-Note": secret.decode()}}),
                CredentialBinding("fixture-key", "fixture.invalid", 443),
            ),
            (GET, CredentialBinding(secret.decode(), "fixture.invalid", 443)),
        ):
            with pytest.raises(ValueError, match="credential value"):
                broker.register(
                    binding=binding,
                    action=proposed,
                    credential=secret,
                    forward=lambda a: None,
                    operator=operator,
                )


def test_credential_caller_ids_do_not_create_a_secret_matching_oracle_or_enter_review(tmp_path):
    collected = []

    class CaptureAudit:
        def record(self, review):
            collected.append(review.as_dict())

    core = Ordin(rest_semantics=RestSemantics(), audit=CaptureAudit())
    with configured(tmp_path, credential=True, selected_core=core) as data:
        service = data[0]
        operator = data[12]
        channels = data[5]
        child = issue(data, rights=data[13])
        secret = b"SYNTHETIC_PRIVATE_CORRELATION_VALUE"
        broker = SwarmCredentialBroker(service, operator=operator)
        route = broker.register(
            binding=CredentialBinding("fixture-key", "fixture.invalid", 443),
            action=GET,
            credential=secret,
            forward=lambda request: None,
            operator=operator,
        )
        for identifier in (secret.decode(), "ordinary-caller-id"):
            reviewed = broker.prepare(
                channels["child"], child.grant_id, route, replace(GET, action_id=identifier)
            )
            assert reviewed.disposition == "execute" and reviewed.admission_id
            assert service.cancel(channels["child"], reviewed.admission_id)
        assert secret.decode() not in json.dumps(collected) + json.dumps(
            service.audit()
        ) + json.dumps(broker.audit())
