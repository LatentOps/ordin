"""Private deployment inputs and MCP framing never become caller authority."""

from copy import deepcopy
import json
import os
from pathlib import Path
import ssl
import sys

import pytest

pytest.importorskip("ordin_swarm")

from ordin_swarm.host_pki import PrivateHostPKI, initialize_private_profile
from ordin_swarm.host_profiles import ToolHostProfile, check_private_directory, load_host_profile
from ordin_swarm.host_protocol import decode_frame, encode_frame


def document(root: Path):
    return {
        "schema_version": "ordin.swarm_tool_host_profile.v1",
        "profile_id": "documents",
        "tenant_id": "local",
        "swarm_id": "reports",
        "task_id": "report",
        "workspace": str(root / "workspace"),
        "files": [
            {"name": "document.txt", "label": "private_code"},
            {"name": "report.txt", "label": "secret"},
        ],
        "actors": [
            {
                "agent_id": "reader",
                "read_files": ["document.txt"],
                "write_files": [],
                "http_routes": [],
                "peers": ["writer"],
            },
            {
                "agent_id": "writer",
                "read_files": [],
                "write_files": ["report.txt"],
                "http_routes": [],
                "peers": [],
            },
        ],
        "http_routes": [],
        "limits": {
            "requests": 128,
            "output_bytes": 1048576,
            "concurrency": 2,
            "lifetime_seconds": 3600,
        },
    }


def route():
    return {
        "route_id": "reference",
        "url": "https://example.com/reference",
        "addresses": ["93.184.216.34"],
        "allow_private_network": False,
        "allow_http": False,
        "response_limit_bytes": 4096,
        "response_label": "public",
        "credential_file": None,
        "ca_file": None,
    }


def test_optional_fixed_tests_are_exact_managed_catalogue_entries(tmp_path):
    value = document(tmp_path)
    value["files"].append({"name": "test_report.py", "label": "private_code"})
    value["test_routes"] = [{"test_id": "report", "selectors": ["test_report.py::test_report"]}]
    value["test_runtime"] = "state/test-runtime"
    value["actors"][1]["test_ids"] = ["report"]
    profile = ToolHostProfile.from_dict(value, configuration_root=tmp_path)
    assert profile.actor("reader").test_ids == ()
    assert profile.actor("writer").test_ids == ("report",)
    assert profile.as_dict() == value
    for change in (
        lambda v: v.update(test_runtime="pki"),
        lambda v: v["actors"][0].update(test_ids=["other"]),
        lambda v: v["test_routes"][0].update(selectors=["../test_report.py"]),
        lambda v: v["test_routes"][0].update(selectors=["-c.py"]),
        lambda v: v["test_routes"][0].update(selectors=["unlisted.py"]),
    ):
        invalid = deepcopy(value)
        change(invalid)
        with pytest.raises(ValueError):
            ToolHostProfile.from_dict(invalid, configuration_root=tmp_path)


def test_profile_roundtrip_preserves_explicit_actor_resource_scopes_without_io(tmp_path):
    source = document(tmp_path)
    profile = ToolHostProfile.from_dict(source, configuration_root=tmp_path)
    assert profile.as_dict() == source
    assert profile.actor("reader").write_files == ()
    assert profile.actor("writer").read_files == ()
    assert not (tmp_path / "workspace").exists()
    with pytest.raises(ValueError):
        profile.actor("operator")
    with pytest.raises(ValueError):
        profile.require_unchanged()


@pytest.mark.parametrize("field", ["operator", "approval", "execute", "callback", "policy"])
def test_profile_rejects_undeclared_authority_or_executable_fields(tmp_path, field):
    source = document(tmp_path)
    source[field] = "approved"
    with pytest.raises(ValueError):
        ToolHostProfile.from_dict(source, configuration_root=tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["actors"][0].update(agent_id="broker"),
        lambda d: d["actors"].append(deepcopy(d["actors"][0])),
        lambda d: d["actors"][0].update(peers=["reader"]),
        lambda d: d["actors"][0].update(peers=["missing"]),
        lambda d: d["actors"][0].update(read_files=["../private.pem"]),
        lambda d: d["actors"][0].update(write_files=["unconfigured.txt"]),
        lambda d: d["actors"][0].update(http_routes=["unconfigured"]),
        lambda d: d["files"].append({"name": "document.txt", "label": "public"}),
        lambda d: d["limits"].update(requests=True),
        lambda d: d["limits"].update(lifetime_seconds=3601),
        lambda d: d.update(workspace="../workspace"),
        lambda d: d["files"][0].update(label="approved"),
    ],
)
def test_profile_rejects_ambiguous_or_expanding_configuration(tmp_path, change):
    source = document(tmp_path)
    change(source)
    with pytest.raises(ValueError):
        ToolHostProfile.from_dict(source, configuration_root=tmp_path)


def test_profile_network_authority_is_exact_and_pinned_without_dns(tmp_path, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_: pytest.fail("inspection performed DNS"))
    source = document(tmp_path)
    source["http_routes"] = [route()]
    source["actors"][0]["http_routes"] = ["reference"]
    result = ToolHostProfile.from_dict(source, configuration_root=tmp_path)
    assert result.http_routes[0].addresses == ("93.184.216.34",)


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://@example.com/reference"},
        {"url": "https://example.com:0/reference"},
        {"url": "https://example.com/reference?secret=1"},
        {"url": "https://example.com/reference#secret"},
        {"url": "https://example.com/%2e%2e/private"},
        {"url": "https://example.com/a/../private"},
        {"url": "https://example.com/a//b"},
        {"url": "https://example.com/\nprivate"},
        {"addresses": []},
        {"addresses": ["127.0.0.1"]},
        {"addresses": ["169.254.169.254"]},
        {"addresses": ["0.0.0.0"], "allow_private_network": True},
        {"addresses": ["::ffff:7f00:1"], "allow_private_network": True},
        {"url": "http://example.com/reference", "allow_http": True},
        {"credential_file": "../token"},
        {"ca_file": "/unselected/ca.pem"},
    ],
)
def test_profile_network_confusion_and_unapproved_private_routes_fail(tmp_path, changes):
    source = document(tmp_path)
    selected = route()
    selected.update(changes)
    source["http_routes"] = [selected]
    with pytest.raises(ValueError):
        ToolHostProfile.from_dict(source, configuration_root=tmp_path)


def test_explicit_owned_http_is_loopback_only_and_cannot_use_credentials(tmp_path):
    source = document(tmp_path)
    selected = route()
    selected.update(
        url="http://127.0.0.1:8080/reference",
        addresses=["127.0.0.1"],
        allow_private_network=True,
        allow_http=True,
    )
    source["http_routes"] = [selected]
    assert ToolHostProfile.from_dict(source, configuration_root=tmp_path).http_routes
    selected["credential_file"] = "tokens/reference"
    with pytest.raises(ValueError):
        ToolHostProfile.from_dict(source, configuration_root=tmp_path)


def test_actual_private_profile_bytes_are_rechecked_and_duplicate_keys_refused(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document(tmp_path)), encoding="utf-8")
    path.chmod(0o600)
    selected = load_host_profile(tmp_path)
    selected.require_unchanged()
    data = document(tmp_path)
    data["limits"]["requests"] += 1
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        selected.require_unchanged()
    path.write_bytes(b'{"schema_version":"a","schema_version":"b"}')
    with pytest.raises(ValueError, match="duplicate"):
        load_host_profile(tmp_path)


@pytest.mark.parametrize(
    "raw",
    [
        b'[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]',
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":null,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","actor":"writer"}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}',
        b'{"jsonrpc":"2.0","id":9007199254740992,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\xff"}}',
    ],
)
def test_mcp_frame_rejects_batches_forged_identity_duplicate_and_noninteroperable_values(raw):
    with pytest.raises(ValueError):
        decode_frame(raw)


def test_mcp_frame_roundtrip_has_an_explicit_finite_wire_limit():
    request = {"jsonrpc": "2.0", "id": "one", "method": "ping"}
    assert decode_frame(encode_frame(request)) == request
    with pytest.raises(ValueError):
        encode_frame({"data": "x" * 131072})
    with pytest.raises(ValueError):
        decode_frame(b"x" * 131073)


def test_private_pki_requires_supported_ownership_and_never_replaces_an_install(tmp_path):
    if sys.platform == "linux":
        with pytest.raises(ValueError, match="new explicit"):
            initialize_private_profile(tmp_path, document(tmp_path))
    else:
        target = tmp_path / "new"
        with pytest.raises(ValueError, match="supported Linux"):
            initialize_private_profile(target, document(target))
        assert not target.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="real private Linux PKI bootstrap")
def test_private_pki_is_unique_mutual_tls_and_changes_do_not_reuse_identity(tmp_path):
    if not Path("/usr/bin/openssl").is_file():
        pytest.fail("supported Linux host requires its declared OpenSSL tool")
    before = ssl.create_default_context().get_ca_certs(binary_form=True)
    target = tmp_path / "installation"
    initialize_private_profile(target, document(target))
    profile = load_host_profile(target)
    pki = PrivateHostPKI(profile)
    assert pki.fingerprint("reader") != pki.fingerprint("writer")
    with pki.pair("reader") as (server, client):
        assert server.getpeercert(binary_form=True)
        assert client.getpeercert(binary_form=True)
    assert ssl.create_default_context().get_ca_certs(binary_form=True) == before
    for path in (target / "pki").iterdir():
        assert path.stat().st_uid == os.geteuid()
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError):
        pki.fingerprint("unconfigured")
    key = target / "pki" / "reader" / "key.pem"
    key.write_bytes(key.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="changed"):
        pki.require_unchanged()


@pytest.mark.skipif(sys.platform != "linux", reason="real isolated principal PKI layout")
def test_principal_names_cannot_collide_with_another_principals_key_file(tmp_path):
    target = tmp_path / "installation"
    selected = document(target)
    selected["actors"][0].update(agent_id="server-key", peers=["ca-key"])
    selected["actors"][1].update(agent_id="ca-key")
    initialize_private_profile(target, selected)
    pki = PrivateHostPKI(load_host_profile(target))
    assert b"PRIVATE KEY" in (target / "pki/server/key.pem").read_bytes()
    assert b"PRIVATE KEY" in (target / "pki/ca-key.pem").read_bytes()
    assert b"CERTIFICATE" in (target / "pki/server-key/cert.pem").read_bytes()
    assert pki.fingerprint("server-key") != pki.fingerprint("ca-key")
    with pki.pair("server-key") as (server, client):
        assert server.version() and client.version()


@pytest.mark.skipif(os.name != "posix", reason="POSIX private ancestor ownership boundary")
def test_private_leaf_does_not_hide_an_untrusted_writable_parent(tmp_path):
    parent = tmp_path / "mutable-parent"
    parent.mkdir(mode=0o700)
    private = parent / "private"
    private.mkdir(mode=0o700)
    parent.chmod(0o777)
    with pytest.raises(ValueError, match="mutable ancestor"):
        check_private_directory(private)
