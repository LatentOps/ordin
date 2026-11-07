import json
import subprocess
import sys
from decimal import Decimal
from types import MappingProxyType

import pytest

from ordin.agent import AgentGate
from ordin.api import Ordin
from ordin.mcp_proxy import (
    APPROVAL_REQUIRED_CODE,
    BLOCKED_CODE,
    MAX_MCP_JSON_DEPTH,
    MCPStdioSafetyProxy,
    _parse_jsonrpc_line,
    run_stdio_proxy,
)
from ordin.tool_calls import ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry


def _call(request_id=1, *, name="read_file", arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": {} if arguments is None else arguments,
        },
    }


def _read_semantics(server="fixture"):
    return ToolSemanticsRegistry(
        registry_id="mcp-fixture",
        version="1",
        rules=(
            ToolSemanticRule(
                id="fixture-read",
                kind="mcp",
                server=server,
                tool="read_file",
                effects=("filesystem.read",),
                resources=(ToolResourceBinding(argument="path", type="path"),),
            ),
        ),
    )


def test_unrecognized_upstream_result_tag_is_not_persisted_as_evidence():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    assert proxy.process_client_message(_call(arguments={"path": "README.md"})).forward
    observation = proxy.observe_server_message(
        {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "Bearer synthetic-private-value"}}
    )
    assert observation.exit_code is None
    assert observation.metadata["status"] == "unrecognized_result_type"
    assert "synthetic-private-value" not in str(observation.as_dict())


@pytest.mark.parametrize("result", [None, "not-a-result", {"isError": "false"}])
def test_malformed_tool_result_cannot_be_recorded_as_success(result):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    assert proxy.process_client_message(_call(arguments={"path": "README.md"})).forward
    with pytest.raises(ValueError, match="result"):
        proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": result})
    assert proxy.session.snapshot()["observations"]["observations"] == []
    assert proxy.pending_count == 1
    assert not proxy.process_client_message(_call(1)).forward
    observation = proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert observation is not None
    assert proxy.pending_count == 0


def test_invalid_observation_evidence_keeps_request_reserved():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    original = proxy.process_client_message(_call())
    before = proxy.session.snapshot()
    response = {"jsonrpc": "2.0", "id": 1, "result": {}}
    with pytest.raises(ValueError, match="effect"):
        proxy.observe_server_message(response, observed_effects=("invalid effect",))
    assert proxy.pending_count == 1
    assert proxy.session.snapshot() == before
    assert not proxy.process_client_message(_call()).forward
    accepted = proxy.observe_server_message(response, observed_effects=("filesystem.read",))
    assert accepted.action_id == original.action_id
    assert proxy.pending_count == 0
    assert proxy.observe_server_message(response) is None


@pytest.mark.parametrize(
    "error",
    [
        None,
        "private error",
        [],
        {},
        {"code": True, "message": "private error"},
        {"code": "-32000", "message": "private error"},
        {"code": -32000},
        {"code": -32000, "message": None},
    ],
)
def test_malformed_error_keeps_request_and_evidence_unchanged(tmp_path, error):
    from ordin.trace_capture import attach_trace, read_capture

    capture = tmp_path / "capture.db"
    ordin, recorder = attach_trace(
        Ordin(tool_semantics=_read_semantics()), capture, integration="mcp-proxy"
    )
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=AgentGate(ordin), trace=recorder)
    original = proxy.process_client_message(_call())
    before = proxy.session.snapshot()
    with pytest.raises(ValueError, match="error"):
        proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "error": error})
    assert proxy.pending_count == 1
    assert proxy.session.snapshot() == before
    assert [event["event"] for event in read_capture(capture)["events"]] == ["review"]
    assert not proxy.process_client_message(_call()).forward
    observation = proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert observation.action_id == original.action_id
    assert proxy.pending_count == 0


def test_failed_trace_write_does_not_consume_response(tmp_path, monkeypatch):
    from ordin.trace_capture import attach_trace, read_capture

    path = tmp_path / "capture.db"
    ordin, recorder = attach_trace(
        Ordin(tool_semantics=_read_semantics()), path, integration="mcp-proxy"
    )
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=AgentGate(ordin), trace=recorder)
    original = proxy.process_client_message(_call())
    response = {"jsonrpc": "2.0", "id": 1, "result": {}}
    record_observation = recorder.record_observation

    def unavailable(*args, **kwargs):
        raise OSError("capture unavailable")

    monkeypatch.setattr(recorder, "record_observation", unavailable)
    with pytest.raises(OSError, match="capture unavailable"):
        proxy.observe_server_message(response)
    assert proxy.pending_count == 1
    assert not proxy.session.snapshot()["observations"]["observations"]
    monkeypatch.setattr(recorder, "record_observation", record_observation)
    assert proxy.observe_server_message(response).action_id == original.action_id
    assert [event["event"] for event in read_capture(path)["events"]] == ["review", "observation"]


@pytest.mark.parametrize(
    "line",
    [
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list"}',
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}',
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete","name":"read"}}',
        b'{"jsonrpc":"2.0","params":{"arguments":{"path":"/a","path":"/b"}}}',
        rb'{"jsonrpc":"2.0","method":"tools/call","meth\u006fd":"tools/list"}',
    ],
)
def test_jsonrpc_parser_rejects_duplicate_members(line):
    with pytest.raises(ValueError, match="duplicate"):
        _parse_jsonrpc_line(line)


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"-1e9999"])
def test_jsonrpc_parser_rejects_nonfinite_numbers(number):
    with pytest.raises(ValueError, match="finite"):
        _parse_jsonrpc_line(b'{"jsonrpc":"2.0","params":{"value":' + number + b"}}")


def test_jsonrpc_parser_rejects_excessive_nesting_as_a_protocol_error():
    line = b'{"jsonrpc":"2.0","params":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}"
    with pytest.raises(ValueError, match="nesting"):
        _parse_jsonrpc_line(line)


def test_jsonrpc_parser_allows_reused_members_in_distinct_objects():
    message = _parse_jsonrpc_line(b'{"jsonrpc":"2.0","params":[{"value":1.5},{"value":2.5}]}')
    assert message["params"] == [{"value": 1.5}, {"value": 2.5}]


@pytest.mark.parametrize(
    "line",
    [
        rb'{"jsonrpc":"2.0","id":"\ud800","method":"tools/list"}',
        rb'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"\udfff"}}',
        rb'{"jsonrpc":"2.0","id":1,"params":{"nested":[{"\ud800":"value"}]}}',
        rb'{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"\udfff"}]}}',
    ],
)
def test_jsonrpc_parser_rejects_lone_surrogates_in_values_and_keys(line):
    with pytest.raises(ValueError, match="Unicode scalar"):
        _parse_jsonrpc_line(line)


def test_jsonrpc_parser_preserves_valid_supplementary_unicode():
    message = _parse_jsonrpc_line(
        rb'{"jsonrpc":"2.0","id":"\ud83d\ude42","params":{"\ud83d\ude42":"ok"}}'
    )
    assert message["id"] == "🙂"
    assert message["params"] == {"🙂": "ok"}


@pytest.mark.parametrize("message", [_call("\ud800"), _call(name="\udfff")])
def test_direct_proxy_rejects_invalid_unicode_without_losing_the_next_request(message):
    from ordin.mcp_proxy import _encode_jsonrpc

    proxy = MCPStdioSafetyProxy(server_id="fixture")
    rejected = proxy.process_client_message(message)
    assert not rejected.forward
    assert rejected.response["error"]["code"] == -32600
    assert json.loads(_encode_jsonrpc(rejected.response))["error"]["code"] == -32600
    assert proxy.pending_count == 0
    assert proxy.process_client_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).forward


def test_direct_proxy_preserves_a_valid_supplementary_unicode_request_id():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    approved = proxy.process_client_message(_call("🙂", arguments={"path": "README.md"}))
    assert approved.forward
    observed = proxy.observe_server_message({"jsonrpc": "2.0", "id": "🙂", "result": {}})
    assert observed is not None and observed.action_id == approved.action_id
    assert observed.exit_code == 0 and proxy.pending_count == 0


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"\ud800": "value"}},
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"values": [("\udfff",)]}},
        {"jsonrpc": "2.0", "id": 1, "method": "\ud800"},
        {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {"\ud800": 1}},
        {"jsonrpc": "2.0", "method": "\udfff"},
        MappingProxyType(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": MappingProxyType({"nested": (MappingProxyType({"key": "\ud800"}),)}),
            }
        ),
    ],
)
def test_direct_client_unicode_is_checked_before_any_pending_or_session_change(message):
    from ordin.mcp_proxy import _encode_jsonrpc

    proxy = MCPStdioSafetyProxy(server_id="fixture")
    before = proxy.session.snapshot()
    rejected = proxy.process_client_message(message)
    assert not rejected.forward
    assert json.loads(_encode_jsonrpc(rejected.response))["error"]["code"] == -32600
    assert proxy.session.snapshot() == before
    proxy.reset_session()
    assert proxy.process_client_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).forward
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    proxy.reset_session()


@pytest.mark.parametrize(
    "extra",
    [
        {"result": {"content": [{"text": "\ud800"}]}},
        {"result": {"content": [{"\udfff": "value"}]}},
        {"result": MappingProxyType({"nested": (MappingProxyType({"value": "\ud800"}),)})},
        {"error": {"code": -32603, "message": "\ud800"}},
        {"method": "notifications/tools/list_changed", "params": {"value": "\udfff"}},
        {"method": "\ud800"},
    ],
)
def test_direct_server_unicode_is_checked_before_observation_or_nonce_consumption(extra):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    original = proxy.process_client_message(_call(arguments={"path": "README.md"}))
    assert original.forward
    before = proxy.session.snapshot()
    with pytest.raises(ValueError, match="Unicode scalar"):
        proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, **extra})
    assert proxy.pending_count == 1
    assert proxy.session.snapshot() == before
    assert not proxy.process_client_message(_call()).forward
    observed = proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {"content": []}})
    assert observed is not None and observed.action_id == original.action_id
    assert observed.exit_code == 0 and proxy.pending_count == 0


def test_direct_invalid_unicode_cannot_invalidate_discovery_contracts():
    from ordin.mcp_contracts import MCPContractLock, semantics_binding_digest, tool_contract_digest

    semantics = _read_semantics()
    contract = {"name": "read_file", "inputSchema": {"type": "object"}}
    lock = MCPContractLock(
        semantics_binding_digest(semantics, frozenset()),
        {("fixture", "read_file"): tool_contract_digest(contract)},
    )
    proxy = MCPStdioSafetyProxy(
        server_id="fixture",
        gate=AgentGate(Ordin(tool_semantics=semantics)),
        shell_tools=frozenset(),
        contract_lock=lock,
    )
    listing = {"jsonrpc": "2.0", "id": 0, "method": "tools/list"}
    assert proxy.process_client_message(listing).forward
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 0, "result": {"tools": [contract]}})
    assert proxy.contracts.status == "complete"
    original_live = dict(proxy.contracts.live)
    rejected = proxy.process_client_message({**listing, "id": 1, "params": {"\ud800": "value"}})
    assert not rejected.forward
    assert proxy.contracts.status == "complete" and proxy.contracts.live == original_live
    with pytest.raises(ValueError, match="Unicode scalar"):
        proxy.observe_server_message(
            {
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
                "params": {"\udfff": 1},
            }
        )
    assert proxy.contracts.status == "complete" and proxy.contracts.live == original_live
    assert proxy.process_client_message({**listing, "id": 1}).forward
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {"tools": [contract]}})
    assert proxy.contracts.status == "complete"
    proxy.observe_server_message({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    assert proxy.contracts.status == "unverified"
    proxy.reset_session()


@pytest.mark.parametrize("shape", ["mapping-cycle", "list-cycle", "tuple-cycle", "deep"])
def test_direct_container_preflight_is_bounded_and_preserves_retry(shape):
    script = """
from ordin.mcp_proxy import MCPStdioSafetyProxy
shape = SHAPE
if shape == 'mapping-cycle':
    params = {}
    params['again'] = params
elif shape == 'list-cycle':
    params = []
    params.append(params)
elif shape == 'tuple-cycle':
    values = []
    params = (values,)
    values.append(params)
else:
    params = 'value'
    for _ in range(70):
        params = (params,)
proxy = MCPStdioSafetyProxy(server_id='fixture')
decision = proxy.process_client_message({'jsonrpc':'2.0','id':1,'method':'tools/list','params':params})
assert not decision.forward
assert decision.response['error']['code'] == -32600
proxy.reset_session()
assert proxy.process_client_message({'jsonrpc':'2.0','id':1,'method':'tools/list'}).forward
proxy.observe_server_message({'jsonrpc':'2.0','id':1,'result':{'tools':[]}})
proxy.reset_session()
""".replace("SHAPE", repr(shape))
    result = subprocess.run(
        [sys.executable, "-B", "-c", script], text=True, capture_output=True, timeout=10
    )
    assert result.returncode == 0, result.stderr


def test_direct_server_container_cycle_cannot_consume_the_pending_call():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    original = proxy.process_client_message(_call(arguments={"path": "README.md"}))
    assert original.forward
    cycle = []
    cycle.append(cycle)
    before = proxy.session.snapshot()
    with pytest.raises(ValueError, match="cyclic"):
        proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {"content": cycle}})
    assert proxy.session.snapshot() == before and proxy.pending_count == 1
    observed = proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert observed is not None and observed.action_id == original.action_id


def test_valid_direct_mapping_and_tuple_unicode_values_remain_supported():
    from ordin.mcp_proxy import _encode_jsonrpc

    message = MappingProxyType(
        {"jsonrpc": "2.0", "id": "🙂", "method": "ping", "params": {"parts": ({"text": "🙂"},)}}
    )
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    assert proxy.process_client_message(message).forward
    assert json.loads(_encode_jsonrpc(message))["params"] == {"parts": [{"text": "🙂"}]}
    proxy.observe_server_message(MappingProxyType({"jsonrpc": "2.0", "id": "🙂", "result": {}}))
    proxy.reset_session()


@pytest.mark.parametrize("boundary", ["client", "server", "http"])
def test_direct_shared_dag_is_bounded_before_protocol_state_changes(boundary):
    script = """
import faulthandler
print('phase=imports', flush=True)
faulthandler.dump_traceback_later(8)
from unittest.mock import patch
from ordin import AgentGate, Ordin
from ordin.mcp_http import MCPHTTPConfig, MCPHTTPServer, MCP_HTTP_PROTOCOL, HTTPBoundaryError
from ordin.mcp_proxy import MCPStdioSafetyProxy
from ordin.tool_calls import ToolResourceBinding, ToolSemanticRule, ToolSemanticsRegistry
print('phase=imports_ready', flush=True)
boundary = BOUNDARY
graph = ['text']
for _ in range(40):
    graph = [graph, graph]
print('phase=graph_ready', flush=True)
if boundary == 'client':
    proxy = MCPStdioSafetyProxy(server_id='fixture')
    before = proxy.session.snapshot()
    decision = proxy.process_client_message({'jsonrpc':'2.0','id':2,'method':'ping','params':graph})
    assert not decision.forward and decision.response['error']['code'] == -32600
    assert proxy.session.snapshot() == before
    proxy.reset_session()
    assert proxy.process_client_message({'jsonrpc':'2.0','id':2,'method':'ping'}).forward
    proxy.observe_server_message({'jsonrpc':'2.0','id':2,'result':{}})
    proxy.reset_session()
elif boundary == 'server':
    rule = ToolSemanticRule(id='read',kind='mcp',server='fixture',tool='read_file',
        effects=('filesystem.read',),resources=(ToolResourceBinding(argument='path',type='path'),))
    semantics = ToolSemanticsRegistry('dag-test','1',(rule,))
    proxy = MCPStdioSafetyProxy(server_id='fixture',gate=AgentGate(Ordin(tool_semantics=semantics)))
    assert proxy.process_client_message({'jsonrpc':'2.0','id':2,'method':'tools/call',
        'params':{'name':'read_file','arguments':{'path':'README.md'}}}).forward
    before = proxy.session.snapshot()
    try:
        proxy.observe_server_message({'jsonrpc':'2.0','id':2,
            'result':{'content':[],'structuredContent':{'graph':graph}}})
    except ValueError as exc:
        assert 'maximum message size' in str(exc)
    else:
        raise AssertionError('server accepted enormous logical JSON expansion')
    assert proxy.pending_count == 1 and proxy.session.snapshot() == before
    observed = proxy.observe_server_message({'jsonrpc':'2.0','id':2,'result':{'content':[]}})
    assert observed.exit_code == 0 and proxy.pending_count == 0
else:
    print('phase=http_bind', flush=True)
    # This observer guard needs a real listener, not reverse-DNS metadata.
    with patch('socket.getfqdn', return_value='localhost'):
        server = MCPHTTPServer(MCPHTTPConfig('fixture','http://127.0.0.1:1/mcp',port=0))
    print('phase=http_bound', flush=True)
    print('phase=http_session', flush=True)
    session = server.new_session('fixture-credential','init')
    print('phase=http_session_ready', flush=True)
    try:
        print('phase=http_initialize_request', flush=True)
        assert session.reviewer.process_client_message({'jsonrpc':'2.0','id':'init',
            'method':'initialize'}).forward
        before = session.reviewer.session.snapshot()
        result = {'protocolVersion':MCP_HTTP_PROTOCOL,'capabilities':{'experimental':{'graph':graph}}}
        try:
            print('phase=http_reject_graph', flush=True)
            server.observe(session,{'jsonrpc':'2.0','id':'init','result':result})
        except HTTPBoundaryError as exc:
            assert exc.code == 'invalid_upstream_protocol'
        else:
            raise AssertionError('HTTP accepted enormous logical JSON expansion')
        print('phase=http_graph_rejected', flush=True)
        assert not session.initialized and not session.failed
        assert session.reviewer.session.snapshot() == before
        print('phase=http_valid_retry', flush=True)
        server.observe(session,{'jsonrpc':'2.0','id':'init',
            'result':{'protocolVersion':MCP_HTTP_PROTOCOL,'capabilities':{}}})
        assert session.initialized
        print('phase=http_reset', flush=True)
        session.reviewer.reset_session()
    finally:
        print('phase=http_drop', flush=True)
        server.drop(session)
        print('phase=http_release', flush=True)
        server.release(session)
        print('phase=http_close', flush=True)
        server.server_close()
        print('phase=http_closed', flush=True)
faulthandler.cancel_dump_traceback_later()
print('phase=complete', flush=True)
""".replace("BOUNDARY", repr(boundary))
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-c", script], text=True, capture_output=True, timeout=10
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(
            f"bounded DAG child timed out: stdout={error.stdout!r}; stderr={error.stderr!r}"
        )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("order", ["shallow-first", "deep-first"])
@pytest.mark.parametrize("over_limit", [False, True])
def test_shared_subtree_height_is_checked_on_every_alias_path(order, over_limit):
    shared = []
    for _ in range(4):
        shared = (shared,)
    deep = shared
    for _ in range(MAX_MCP_JSON_DEPTH - 2 - 4 + int(over_limit)):
        deep = [deep]
    params = (
        {"shallow": shared, "deep": deep}
        if order == "shallow-first"
        else {"deep": deep, "shallow": shared}
    )
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    before = proxy.session.snapshot()
    decision = proxy.process_client_message(
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": params}
    )
    assert decision.forward is not over_limit
    assert proxy.session.snapshot() == before
    if over_limit:
        assert "nesting" in decision.response["error"]["message"]
        proxy.reset_session()
    else:
        proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
        proxy.reset_session()


@pytest.mark.parametrize(
    "shared", [{"text": "🙂"}, ["🙂"], ("🙂",), MappingProxyType({"text": "🙂"})]
)
def test_small_shared_container_aliases_remain_supported_without_normalization(shared):
    from ordin.mcp_proxy import _encode_jsonrpc

    params = {"left": shared, "right": shared}
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    assert proxy.process_client_message(
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": params}
    ).forward
    assert params["left"] is shared and params["right"] is shared
    encoded = json.loads(
        _encode_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": params})
    )
    assert encoded["params"]["left"] == encoded["params"]["right"]
    assert "🙂" in str(encoded)
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    proxy.reset_session()


def test_preflight_cache_eviction_preserves_legal_shared_inputs():
    from ordin.mcp_proxy import MAX_MCP_PREFLIGHT_CACHE_ITEMS, _encode_jsonrpc

    shared = ["🙂"]
    values = [shared, *([] for _ in range(MAX_MCP_PREFLIGHT_CACHE_ITEMS + 1)), shared]
    message = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": values}
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    assert proxy.process_client_message(message).forward
    assert len(json.loads(_encode_jsonrpc(message))["params"]) == len(values)
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    proxy.reset_session()


def test_preflight_preserves_legal_compact_wire_numbers(monkeypatch):
    import ordin.mcp_proxy as module

    raw = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[' + b",".join([b"1e9"] * 10) + b"]}"
    monkeypatch.setattr(module, "MAX_MCP_MESSAGE_BYTES", len(raw))
    message = _parse_jsonrpc_line(raw)
    assert len(module._encode_jsonrpc(message)) > len(raw)
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    assert proxy.process_client_message(message).forward
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    proxy.reset_session()


@pytest.fixture(
    params=[
        pytest.param(b"raw", id="bytes"),
        pytest.param(bytearray(b"raw"), id="bytearray"),
        pytest.param({"value"}, id="set"),
        pytest.param({("tuple", "key"): "value"}, id="tuple-key"),
        pytest.param({1: "value"}, id="integer-key"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param(Decimal("0.1"), id="decimal"),
        pytest.param(object(), id="opaque-object"),
    ]
)
def unencodable_direct_json(request):
    return request.param


def test_direct_client_unencodable_values_cannot_reserve_an_id(unencodable_direct_json):
    from ordin.mcp_proxy import _encode_jsonrpc

    proxy = MCPStdioSafetyProxy(server_id="fixture")
    before = proxy.session.snapshot()
    message = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": unencodable_direct_json}
    rejected = proxy.process_client_message(message)
    assert not rejected.forward
    assert json.loads(_encode_jsonrpc(rejected.response))["error"]["code"] == -32600
    with pytest.raises(ValueError):
        _encode_jsonrpc(message)
    assert proxy.session.snapshot() == before
    proxy.reset_session()
    assert proxy.process_client_message({"jsonrpc": "2.0", "id": 1, "method": "ping"}).forward
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    proxy.reset_session()


def test_direct_server_unencodable_values_cannot_become_completion(unencodable_direct_json):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    approved = proxy.process_client_message(_call(arguments={"path": "README.md"}))
    assert approved.forward
    before = proxy.session.snapshot()
    with pytest.raises(ValueError):
        proxy.observe_server_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"structuredContent": {"value": unencodable_direct_json}},
            }
        )
    assert proxy.pending_count == 1 and proxy.session.snapshot() == before
    observed = proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert observed is not None and observed.action_id == approved.action_id
    assert observed.exit_code == 0 and proxy.pending_count == 0


def test_direct_unencodable_large_integer_is_rejected_before_state_changes():
    from ordin.mcp_proxy import _encode_jsonrpc

    if not hasattr(sys, "set_int_max_str_digits"):
        pytest.skip("interpreter has no configurable integer encoding limit")
    original_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        value = 10**700
        with pytest.raises(ValueError):
            json.dumps(value)
        proxy = MCPStdioSafetyProxy(server_id="fixture")
        before = proxy.session.snapshot()
        message = {"jsonrpc": "2.0", "id": value, "method": "ping"}
        rejected = proxy.process_client_message(message)
        assert not rejected.forward
        assert json.loads(_encode_jsonrpc(rejected.response))["id"] is None
        assert proxy.session.snapshot() == before
        proxy.reset_session()
    finally:
        sys.set_int_max_str_digits(original_limit)


def test_jsonrpc_parser_enforces_the_documented_nesting_boundary():
    prefix = b'{"jsonrpc":"2.0","params":'
    nested = b"[" * MAX_MCP_JSON_DEPTH + b"0" + b"]" * MAX_MCP_JSON_DEPTH
    assert _parse_jsonrpc_line(prefix + nested + b"}")["jsonrpc"] == "2.0"
    with pytest.raises(ValueError, match="nesting"):
        _parse_jsonrpc_line(prefix + b"[" + nested + b"]}")


@pytest.mark.parametrize("request_id", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_request_ids_are_rejected_by_the_direct_proxy_api(request_id):
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    decision = proxy.process_client_message(_call(request_id=request_id))
    assert not decision.forward
    assert decision.response["error"]["code"] == -32600


@pytest.mark.parametrize(
    "timeout",
    [float("nan"), float("inf"), float("-inf"), 0, -1, 1e300, 10**1000, True, None, "1"],
    ids=[
        "nan",
        "infinity",
        "negative-infinity",
        "zero",
        "negative",
        "huge-float",
        "huge-integer",
        "boolean",
        "null",
        "text",
    ],
)
def test_invalid_shutdown_timeout_is_rejected_before_launch(monkeypatch, timeout):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid shutdown configuration launched an upstream process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="finite, positive"):
        run_stdio_proxy(
            MCPStdioSafetyProxy(server_id="fixture"), ["never-run"], shutdown_timeout=timeout
        )


@pytest.mark.parametrize("timeout", ["nan", "inf", "-inf", "1e300"])
def test_stdio_cli_reports_unsupported_timeouts_as_configuration_errors(timeout):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            f"--shutdown-timeout={timeout}",
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(99)",
        ],
        input="",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "finite, positive" in result.stderr
    assert "Traceback" not in result.stderr


def test_stdio_proxy_rejects_ambiguous_client_json_and_continues():
    server = (
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " message=json.loads(line)\n"
        " print(json.dumps({'jsonrpc':'2.0','id':message['id'],"
        "'result':{'received':line.rstrip('\\n')}}),flush=True)\n"
    )
    ambiguous = '{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list"}\n'
    valid = '{ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }'
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--",
            sys.executable,
            "-c",
            server,
        ],
        input=ambiguous + valid + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    messages = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(messages) == 2
    assert messages[0]["id"] is None
    assert messages[0]["error"]["code"] == -32700
    assert messages[1] == {"jsonrpc": "2.0", "id": 2, "result": {"received": valid}}


@pytest.mark.parametrize("bad_call", [_call("\ud800"), _call(name="\udfff")])
def test_stdio_proxy_rejects_invalid_unicode_and_processes_next_request(bad_call):
    server = (
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " message=json.loads(line)\n"
        " print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':{}}),flush=True)\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--",
            sys.executable,
            "-c",
            server,
        ],
        input=json.dumps(bad_call) + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n',
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    messages = [json.loads(line) for line in result.stdout.splitlines()]
    assert messages[0]["id"] is None
    assert messages[0]["error"]["code"] == -32700
    assert messages[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_stdio_proxy_does_not_forward_invalid_unicode_from_upstream():
    line = r'{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"\ud800"}]}}'
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--",
            sys.executable,
            "-c",
            f"print({line!r},flush=True)",
        ],
        input="",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "upstream protocol error" in result.stderr


@pytest.mark.parametrize(
    "line",
    [
        '{"jsonrpc":"2.0","id":1,"result":{},"result":{"isError":true}}',
        '{"jsonrpc":"2.0","id":1,"result":{"value":NaN}}',
    ],
)
def test_stdio_proxy_does_not_forward_ambiguous_upstream_json(line):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--",
            sys.executable,
            "-c",
            f"print({line!r}, flush=True)",
        ],
        input="",
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "upstream protocol error" in result.stderr


def test_non_tool_protocol_messages_forward_unchanged():
    proxy = MCPStdioSafetyProxy(server_id="fixture")
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

    decision = proxy.process_client_message(message)

    assert decision.forward is True
    assert decision.response is None


def test_unknown_tool_requires_approval_without_reaching_upstream():
    proxy = MCPStdioSafetyProxy(server_id="fixture")

    decision = proxy.process_client_message(_call(name="future_tool"))

    assert decision.forward is False
    assert decision.response is not None
    assert decision.response["error"]["code"] == APPROVAL_REQUIRED_CODE
    assert decision.response["error"]["data"]["ordin"]["decision"] == "ask"
    assert proxy.pending_count == 0


def test_exact_server_tool_semantics_allow_and_bind_resource():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=gate)

    decision = proxy.process_client_message(_call(arguments={"path": "/tmp/a.txt"}))

    assert decision.forward is True
    assert decision.action_id is not None
    assert proxy.pending_count == 1


@pytest.mark.parametrize(("request_id", "response_id"), [(1, 1.0), (1.0, 1), (0, -0.0), (-0.0, 0)])
def test_equivalent_numeric_response_ids_settle_the_original_call(request_id, response_id):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    decision = proxy.process_client_message(_call(request_id=request_id))
    assert decision.forward

    observation = proxy.observe_server_message(
        {"jsonrpc": "2.0", "id": response_id, "result": {"content": []}}
    )

    assert observation is not None
    assert observation.action_id == decision.action_id
    assert proxy.pending_count == 0


@pytest.mark.parametrize(("first_id", "second_id"), [(1, 1.0), (1.0, 1), (0, -0.0)])
def test_equivalent_numeric_request_ids_are_duplicate_inflight_calls(first_id, second_id):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    assert proxy.process_client_message(_call(request_id=first_id)).forward

    duplicate = proxy.process_client_message(_call(request_id=second_id))

    assert not duplicate.forward
    assert duplicate.response["error"]["code"] == -32600
    assert proxy.pending_count == 1


@pytest.mark.parametrize(("first_id", "second_id"), [(1, "1"), (2**53, 2**53 + 1), (1, 1.5)])
def test_distinct_request_ids_do_not_alias(first_id, second_id):
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    first = proxy.process_client_message(_call(request_id=first_id))
    second = proxy.process_client_message(_call(request_id=second_id))
    assert first.forward and second.forward
    assert proxy.pending_count == 2
    for request_id, decision in [(second_id, second), (first_id, first)]:
        observation = proxy.observe_server_message(
            {"jsonrpc": "2.0", "id": request_id, "result": {"content": []}}
        )
        assert observation.action_id == decision.action_id
    assert proxy.pending_count == 0


def test_server_identity_mismatch_loses_trusted_semantics():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics(server="trusted")))
    proxy = MCPStdioSafetyProxy(server_id="mutated", gate=gate)

    decision = proxy.process_client_message(_call())

    assert decision.forward is False
    assert decision.response is not None
    assert decision.response["error"]["code"] == APPROVAL_REQUIRED_CODE
    assert decision.response["error"]["data"]["ordin"]["decision"] == "ask"


def test_tool_identity_whitespace_is_not_forwarded_with_trusted_semantics():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=gate)

    decision = proxy.process_client_message(_call(name=" read_file "))

    assert decision.forward is False
    assert decision.response["error"]["code"] == APPROVAL_REQUIRED_CODE
    assert proxy.pending_count == 0


def test_explicit_shell_block_never_reaches_upstream():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture",
        shell_tools=frozenset({"execute_command"}),
    )

    decision = proxy.process_client_message(
        _call(name="execute_command", arguments={"command": "rm -rf /"})
    )

    assert decision.forward is False
    assert decision.response is not None
    assert decision.response["error"]["code"] == BLOCKED_CODE
    assert decision.response["error"]["data"]["ordin"]["decision"] == "block"


def test_duplicate_inflight_and_malformed_calls_fail_closed():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=gate)

    first = proxy.process_client_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file"}}
    )
    assert first.forward is True

    duplicate = proxy.process_client_message(_call(request_id=1))
    assert duplicate.forward is False
    assert duplicate.response is not None
    assert duplicate.response["error"]["code"] == -32600

    missing_name = proxy.process_client_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}}
    )
    assert missing_name.forward is False
    assert missing_name.response is not None
    assert missing_name.response["error"]["code"] == -32600


def test_pending_action_survives_history_pressure_and_records_its_result():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture",
        gate=AgentGate(Ordin(tool_semantics=_read_semantics())),
        shell_tools=frozenset({"shell"}),
    )
    original = proxy.process_client_message(_call(1))
    assert original.forward
    for request_id in range(2, 33):
        assert not proxy.process_client_message(_call(request_id, name="untrusted")).forward
    full = proxy.session.snapshot()
    assert len(full["history"]["actions"]) == 32
    refused = proxy.process_client_message(_call(33))
    assert not refused.forward
    assert proxy.session.snapshot() == full
    observation = proxy.observe_server_message(
        {"jsonrpc": "2.0", "id": 1, "result": {}}, observed_effects=("secret.read",)
    )
    assert observation.action_id == original.action_id
    assert proxy.session.snapshot()["observations"]["observations"][0]["effects"] == ["secret.read"]
    assert proxy.process_client_message(_call(34)).forward
    assert len(proxy.session.snapshot()["history"]["actions"]) == 32


def test_out_of_order_settlement_keeps_oldest_pending_action_reserved():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    assert proxy.process_client_message(_call(1)).forward
    assert proxy.process_client_message(_call(2)).forward
    for request_id in range(3, 33):
        proxy.process_client_message(_call(request_id, name="untrusted"))
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 2, "result": {}})
    assert not proxy.process_client_message(_call(33)).forward
    assert proxy.pending_count == 1
    proxy.observe_server_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert proxy.process_client_message(_call(33)).forward
    assert len(proxy.session.snapshot()["history"]["actions"]) == 32


def test_full_history_can_evict_settled_proposals_while_newer_calls_are_pending():
    proxy = MCPStdioSafetyProxy(
        server_id="fixture", gate=AgentGate(Ordin(tool_semantics=_read_semantics()))
    )
    for request_id in range(1, 32):
        proxy.process_client_message(_call(request_id, name="untrusted"))
    assert proxy.process_client_message(_call(32)).forward
    assert proxy.process_client_message(_call(33)).forward
    assert proxy.pending_count == 2
    assert len(proxy.session.snapshot()["history"]["actions"]) == 32


def test_tool_result_creates_linked_redacted_observation(tmp_path):
    observations = tmp_path / "observations.jsonl"
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(
        server_id="fixture",
        gate=gate,
        observations_path=observations,
    )
    decision = proxy.process_client_message(
        _call(request_id="req-1", arguments={"path": "/secret"})
    )
    assert decision.forward is True

    observation = proxy.observe_server_message(
        {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"content": [{"type": "text", "text": "sensitive output"}]},
        }
    )

    assert observation is not None
    assert observation.action_id == decision.action_id
    assert observation.exit_code == 0
    assert observation.metadata["status"] == "success"
    assert "content" not in observation.metadata
    persisted = json.loads(observations.read_text(encoding="utf-8"))
    assert persisted["action_id"] == decision.action_id
    assert "sensitive output" not in observations.read_text(encoding="utf-8")
    assert proxy.pending_count == 0


def test_tool_and_protocol_errors_are_observed_without_error_payload():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=gate)

    first = proxy.process_client_message(_call(request_id=1))
    assert first.forward is True
    tool_error = proxy.observe_server_message(
        {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": ["secret"]}}
    )
    assert tool_error is not None
    assert tool_error.exit_code == 1
    assert tool_error.metadata["status"] == "tool_error"

    second = proxy.process_client_message(_call(request_id=2))
    assert second.forward is True
    protocol_error = proxy.observe_server_message(
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "secret"}}
    )
    assert protocol_error is not None
    assert protocol_error.exit_code is None
    assert protocol_error.metadata["status"] == "protocol_error"
    assert "error" not in protocol_error.metadata


def test_multi_round_results_are_not_misreported_as_completed_success():
    gate = AgentGate(Ordin(tool_semantics=_read_semantics()))
    proxy = MCPStdioSafetyProxy(server_id="fixture", gate=gate)

    task_decision = proxy.process_client_message(_call(request_id=3))
    assert task_decision.forward is True
    task_observation = proxy.observe_server_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"resultType": "task", "taskId": "opaque-task", "status": "working"},
        }
    )
    assert task_observation is not None
    assert task_observation.exit_code is None
    assert task_observation.metadata["status"] == "task_accepted"
    assert task_observation.metadata["result_type"] == "task"

    input_decision = proxy.process_client_message(_call(request_id=4))
    assert input_decision.forward is True
    input_observation = proxy.observe_server_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"resultType": "input_required", "prompt": "sensitive prompt"},
        }
    )
    assert input_observation is not None
    assert input_observation.exit_code is None
    assert input_observation.metadata["status"] == "input_required"
    assert input_observation.metadata["result_type"] == "input_required"
    assert "prompt" not in input_observation.metadata


def test_stdio_proxy_end_to_end_forwards_discovery_and_allowed_call(tmp_path):
    semantics = tmp_path / "semantics.json"
    semantics.write_text(
        json.dumps(
            {
                "schema_version": "ordin.tool_semantics.v1",
                "registry_id": "fixture",
                "version": "1",
                "rules": [
                    {
                        "id": "read",
                        "kind": "mcp",
                        "server": "fixture",
                        "tool": "read_file",
                        "effects": ["filesystem.read"],
                        "resources": [{"argument": "path", "type": "path"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    observations = tmp_path / "observations.jsonl"
    server_code = r"""
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "tools/list":
        result = {"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "fixture-secret"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result}), flush=True)
"""
    messages = (
        "\n".join(
            json.dumps(item)
            for item in [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                _call(request_id=2, arguments={"path": "/tmp/example"}),
            ]
        )
        + "\n"
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--semantics",
            str(semantics),
            "--observations",
            str(observations),
            "--",
            sys.executable,
            "-c",
            server_code,
        ],
        input=messages,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stderr
    output = [json.loads(line) for line in completed.stdout.splitlines()]
    assert output[0]["id"] == 1
    assert output[0]["result"]["tools"][0]["name"] == "read_file"
    assert output[1]["id"] == 2
    assert output[1]["result"]["content"][0]["text"] == "fixture-secret"
    saved = json.loads(observations.read_text(encoding="utf-8"))
    assert saved["metadata"]["tool"] == "read_file"
    assert "fixture-secret" not in observations.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("server_code", "expected_code"),
    [
        ("pass", 0),
        ("raise SystemExit(7)", 7),
        ("import time; print('invalid-json', flush=True); time.sleep(30)", 1),
    ],
)
def test_stdio_proxy_exits_when_upstream_stops_with_client_input_open(server_code, expected_code):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "ordin.mcp_proxy",
            "--server-id",
            "fixture",
            "--shutdown-timeout",
            "0.2",
            "--",
            sys.executable,
            "-c",
            server_code,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # A persistent MCP client keeps stdin open while waiting for a response.
        assert process.wait(timeout=5) == expected_code
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()
