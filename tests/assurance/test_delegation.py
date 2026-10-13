"""Full-domain subset, private issuance, immutable lifecycle and host quotas."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from ordin.assurance import (
    DelegationAuthority,
    DelegationVerification,
    DelegationIssuer,
    DelegationLimits,
    HostEvidenceSource,
    IssuedDelegation,
    verify_delegation_subset,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import (
    FilesystemCapability,
    NetworkCapability,
    ProcessCapability,
    PrivilegeCapability,
    CredentialBinding,
    ToolCapability,
)
from ordin.runtime_requests_v2 import RequestAuthority, NetworkAuthorityGrant

from .test_profiles import REPO, POLICY_HASH, approve, selected, config_profile


def maximum():
    return DelegationAuthority(
        RuntimeCapabilityBoundary(
            "parent",
            filesystem=(FilesystemCapability("read", "/fixture", "prefix"),),
            tools=(ToolCapability("fixture", None, "read_file"),),
            filesystem_semantics="lexical_prefix",
            runtime_filesystem_guarantees=True,
        )
    )


def child_max():
    return DelegationAuthority(
        replace(
            maximum().capability,
            boundary_id="child",
            filesystem=(FilesystemCapability("read", "/fixture/source", "exact"),),
        )
    )


def issuer_fixture(tmp_path, *, limits=None, expires=200):
    profile = approve(selected(tmp_path, config_profile()))
    source = HostEvidenceSource("parent", REPO, "a" * 64, 0, POLICY_HASH, profile.selection_digest)
    clock = [100]
    issuer = DelegationIssuer(
        source, profile, maximum(), maximum(), clock=lambda: clock[0], limits=limits
    )
    root = issuer.authorize_root(maximum(), grant_id="root", expires_at=expires)
    child_source = replace(source, principal="child", session_digest="d" * 64)
    return issuer, root, source, child_source, clock


def test_child_subset_requires_all_parent_operator_task_domains():
    parent = maximum()
    result = verify_delegation_subset(child_max(), parent, parent, parent)
    assert result.ok and all(result.coverage.values())
    assert DelegationVerification.from_dict(result.as_dict()) == result
    cases = (
        replace(
            child_max(),
            capability=replace(
                child_max().capability,
                filesystem=(FilesystemCapability("read", "/fixture2/source", "exact"),),
            ),
        ),
        replace(
            child_max(),
            capability=replace(
                child_max().capability,
                filesystem=(FilesystemCapability("delete", "/fixture/source", "exact"),),
            ),
        ),
        replace(
            child_max(),
            capability=replace(
                child_max().capability, tools=(ToolCapability("fixture", None, "write_file"),)
            ),
        ),
        replace(
            child_max(),
            capability=replace(
                child_max().capability,
                process=ProcessCapability(True, ("/fixture/bin/tool",), False),
            ),
        ),
        replace(
            child_max(),
            capability=replace(child_max().capability, privilege=PrivilegeCapability(True, 0)),
        ),
        replace(
            child_max(),
            capability=replace(
                child_max().capability,
                credentials=(CredentialBinding("fixture-key", "outside.invalid", 443),),
            ),
        ),
    )
    for candidate in cases:
        assert not verify_delegation_subset(candidate, parent, parent, parent).ok
    smaller_task = DelegationAuthority(
        replace(
            parent.capability, filesystem=(FilesystemCapability("read", "/fixture/docs", "prefix"),)
        )
    )
    assert not verify_delegation_subset(child_max(), parent, parent, smaller_task).ok


def test_unknown_domains_and_unbounded_child_rights_are_not_dropped():
    parent = maximum()
    any_binary = replace(
        child_max(), capability=replace(child_max().capability, allow_any_executable=True)
    )
    result = verify_delegation_subset(any_binary, parent, parent, parent)
    assert not result.ok and not result.coverage["process"]
    wildcard = replace(
        child_max(),
        network_grants=(
            NetworkAuthorityGrant("*.fixture.invalid", 443, "rest", "read", ("GET",), ("/docs",)),
        ),
    )
    result = verify_delegation_subset(wildcard, parent, parent, parent)
    assert result.result == "unsupported" and not result.coverage["network"]
    unknown = replace(
        child_max(),
        capability=replace(
            child_max().capability, filesystem=(FilesystemCapability("unknown", None, "unknown"),)
        ),
    )
    assert not verify_delegation_subset(unknown, parent, parent, parent).ok


def test_http_method_path_and_protocol_rights_are_exact():
    rest = NetworkCapability("fixture.invalid", 443, "rest", "read", ("GET",), ("/docs",))
    parent = DelegationAuthority(RuntimeCapabilityBoundary("parent", network=(rest,)))
    assert verify_delegation_subset(parent, parent, parent, parent).ok
    for new in (
        replace(rest, access="write", methods=("POST",), paths=("/deploy",)),
        replace(rest, paths=("/docs2",)),
        replace(rest, port=444),
    ):
        candidate = DelegationAuthority(replace(parent.capability, network=(new,)))
        assert not verify_delegation_subset(candidate, parent, parent, parent).ok
    tcp = DelegationAuthority(
        RuntimeCapabilityBoundary(
            "tcp", network=(NetworkCapability("fixture.invalid", 443, "tcp", "write"),)
        )
    )
    assert not verify_delegation_subset(parent, tcp, tcp, tcp).ok


def test_overlapping_network_rights_permit_only_a_verified_exact_intersection():
    get = NetworkCapability("fixture.invalid", 443, "rest", "read", ("GET",), ("/docs",))
    parent = DelegationAuthority(
        RuntimeCapabilityBoundary("parent", network=(replace(get, methods=("GET", "HEAD")),))
    )
    operator = DelegationAuthority(
        RuntimeCapabilityBoundary("operator", network=(get, replace(get, paths=("/status",))))
    )
    task = DelegationAuthority(
        RuntimeCapabilityBoundary("task", network=(get, replace(get, methods=("HEAD",))))
    )
    child = DelegationAuthority(RuntimeCapabilityBoundary("child", network=(get,)))
    assert verify_delegation_subset(child, parent, operator, task).ok
    widened = replace(
        child,
        capability=replace(child.capability, network=(replace(get, methods=("GET", "HEAD")),)),
    )
    assert not verify_delegation_subset(widened, parent, operator, task).ok


def test_request_arguments_versions_and_approval_cannot_expand():
    body = {"jsonrpc": "2.0", "id": 1, "method": "lookup", "params": {"id": "a"}}
    request = RequestAuthority.from_body("json-rpc", "https://fixture.invalid/rpc", body)
    network = NetworkCapability("fixture.invalid", 443, "json-rpc", "write", ("POST",), ("/rpc",))
    parent = DelegationAuthority(
        RuntimeCapabilityBoundary("rpc", network=(network,)), (request,), requires_approval=True
    )
    assert verify_delegation_subset(parent, parent, parent, parent).ok
    candidate = replace(
        parent,
        requests=(
            RequestAuthority.from_body(
                "json-rpc", "https://fixture.invalid/rpc", {**body, "params": {"id": "b"}}
            ),
        ),
    )
    assert not verify_delegation_subset(candidate, parent, parent, parent).ok
    no_approval = replace(parent, requires_approval=False)
    result = verify_delegation_subset(no_approval, parent, parent, parent)
    assert (
        result.result == "exceeds_boundary"
        and "delegation.parent_approval_removed" in result.reason_codes
    )


def test_host_issuance_json_and_mutation_never_restore_authority(tmp_path):
    issuer, root, source, child_source, clock = issuer_fixture(tmp_path)
    child = issuer.issue_child(root, child_source, child_max(), grant_id="child", expires_at=150)
    issuer.require_current(child, child_source)
    assert child.record.parent_grant_id == "root" and child.record.depth == 1
    with pytest.raises(ValueError, match="JSON cannot issue"):
        IssuedDelegation.from_dict(child.as_dict())
    with pytest.raises(ValueError, match="private host-issued"):
        replace(child, record=replace(child.record, child_principal="forged"))
    with pytest.raises(ValueError, match="scope changed"):
        issuer.require_current(child, replace(child_source, session_digest="e" * 64))
    with pytest.raises(ValueError, match="outside a maximum"):
        issuer.issue_child(
            child,
            replace(child_source, principal="grandchild"),
            DelegationAuthority(
                replace(
                    child_max().capability,
                    filesystem=(FilesystemCapability("read", "/fixture/.env", "exact"),),
                )
            ),
            grant_id="bad",
            expires_at=140,
        )


def test_revocation_expiry_depth_cycles_and_sibling_spoof_fail(tmp_path):
    issuer, root, source, child_source, clock = issuer_fixture(tmp_path)
    child = issuer.issue_child(
        root,
        child_source,
        child_max(),
        grant_id="child",
        expires_at=150,
        maximum_delegation_depth=1,
    )
    with pytest.raises(ValueError, match="depth exhausted"):
        issuer.issue_child(
            child,
            replace(child_source, principal="nested", session_digest="e" * 64),
            child_max(),
            grant_id="nested",
            expires_at=140,
        )
    with pytest.raises(ValueError, match="cycle"):
        issuer.issue_child(
            root,
            replace(child_source, principal=source.principal),
            child_max(),
            grant_id="cycle",
            expires_at=140,
        )
    with pytest.raises(ValueError, match="scope changed"):
        issuer.require_current(child, replace(child_source, principal="sibling"))
    assert issuer.revoke(root) == ("child", "root")
    with pytest.raises(ValueError, match="expired/revoked"):
        issuer.require_current(child, child_source)


def test_expired_parent_and_backward_host_clock_never_issue(tmp_path):
    issuer, root, source, child_source, clock = issuer_fixture(tmp_path, expires=120)
    clock[0] = 120
    with pytest.raises(ValueError, match="expired/revoked"):
        issuer.issue_child(root, child_source, child_max(), grant_id="late", expires_at=130)
    clock[0] = 99
    with pytest.raises(ValueError, match="clock"):
        issuer.require_current(root, source)


def test_concurrent_issuance_enforces_host_child_quota_without_parent_mutation(tmp_path):
    issuer, root, source, child_source, clock = issuer_fixture(
        tmp_path, limits=DelegationLimits(active_children=3)
    )
    before = root.digest

    def create(index):
        try:
            return issuer.issue_child(
                root,
                replace(
                    child_source, principal=f"child{index}", session_digest=f"{index + 1:064x}"
                ),
                child_max(),
                grant_id=f"child{index}",
                expires_at=150,
            )
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(create, range(12)))
    assert sum(v is not None for v in results) == 3
    assert root.digest == before
    issuer.require_current(root, source)
