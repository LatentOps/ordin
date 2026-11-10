"""Fixed synthetic host transitions for the explicitly requested release pilot.

Only this function creates the private fixture. No caller-selected tool, path,
model, credential or imported report can supply a workload or execution permit.
"""

from contextlib import ExitStack, contextmanager
import hashlib
from pathlib import Path
import sys
import time

from ordin._private_storage import private_database

from .host_cli import initialize
from .host_evaluation import evaluation_profile
from .host_pki import _new_file
from .host_profiles import load_host_profile
from .host_protocol import MCPHostSession
from .host_runtime import ManagedToolHost


@contextmanager
def _session(host, name, operator):
    with host._authority.pki.pair(name) as (transport, _):
        client = host.bind_connection(transport, operator=operator)
        session = MCPHostSession(host, client)
        try:
            session.handle(
                {
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "ordin-fixed-release-pilot", "version": "1"},
                    },
                }
            )
            session.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
            yield session, client
        finally:
            session.close()


def _rpc(session, identifier, method, params=None):
    response = session.handle(
        {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}
    )
    if type(response) is not dict or "error" in response:
        raise ValueError("pilot original host request did not complete")
    return response["result"]


def _tool(session, identifier, name, arguments):
    import json

    return json.loads(
        _rpc(session, identifier, "tools/call", {"name": name, "arguments": arguments})["content"][
            0
        ]["text"]
    )


def _counters(profile):
    # Read diagnostics from the original private store, never reconstitute a
    # coordinator, approval or execution handle from these rows.
    with private_database(
        profile.configuration_root / "state" / "budget.sqlite",
        "swarm_budget",
        readonly=True,
        create=False,
        foreign_keys=True,
    ) as connection:
        return {
            row[0]: (row[1], row[2])
            for row in connection.execute("SELECT bucket,held,consumed FROM budget_buckets")
        }


def run_owned_transitions(directory: Path) -> dict:
    """Exercise exact deny/cancel/revoke/restart using original host objects."""
    if sys.platform != "linux" or not directory.is_absolute() or directory.exists():
        raise ValueError("pilot transitions require a new absolute Linux fixture")
    started = time.monotonic()
    data = evaluation_profile(directory, reference_port=1)
    data["http_routes"] = []
    data["actors"][0]["http_routes"] = []
    seed = directory.parent / (directory.name + "-input.txt")
    _new_file(seed, b"Ordin fixed pilot synthetic input; no production data.\n")
    initialize(directory, data, inputs=("source.txt=" + str(seed),))
    profile, operator, cases = load_host_profile(directory), object(), []
    proposal = {
        "name": "report.txt",
        "content": "Ordin fixed pilot report.\n",
        "expected_version": 0,
        "expected_digest": None,
    }
    report = profile.workspace / "report.txt"
    with ExitStack() as stack:
        host = ManagedToolHost(profile, operator=operator, policy_epoch=0, initialize_scope=True)
        stack.callback(host.close)
        writer, original = stack.enter_context(_session(host, "writer", operator))
        human, _ = stack.enter_context(_session(host, "operator", operator))
        pending = _tool(writer, "deny-proposal", "write_artifact", proposal)
        if pending["status"] != "requires_approval":
            raise ValueError("pilot exact write did not require review")
        reference, binding = pending["data"]["request_ref"], pending["data"]["binding_digest"]
        denied = _rpc(
            human,
            "deny",
            "ordin/operator/resolve",
            {
                "request_ref": reference,
                "expected_binding": binding,
                "choice": "deny",
                "idempotency_key": "fixed-pilot-denial",
            },
        )
        fulfilled = _rpc(
            human,
            "denied-fulfill",
            "ordin/operator/fulfill",
            {"request_ref": reference, "expected_binding": binding},
        )
        cases.append(
            {
                "id": "exact_operator_denial",
                "passed": denied["status"] == "completed"
                and denied["data"]["request"]["status"] == "denied"
                and fulfilled["data"]["fulfillment"]["status"] != "completed"
                and not report.exists(),
            }
        )
        pending = _tool(writer, "cancel-proposal", "write_artifact", proposal)
        if pending["status"] != "requires_approval":
            raise ValueError("pilot cancel request was not retained")
        reference = pending["data"]["request_ref"]
        writer.close()
        original_pending = host._approvals[reference]
        cases.append(
            {
                "id": "original_connection_cancels_pending_write",
                "passed": original_pending.result is not None
                and original_pending.result["status"] == "denied"
                and not report.exists(),
            }
        )
        reader, reader_client = stack.enter_context(_session(host, "reader", operator))
        read = _tool(reader, "original-read", "read_file", {"name": "source.txt"})
        if read["status"] != "completed" or not read["physical_enforcement"]:
            raise ValueError("pilot original read worker did not establish its outcome")
        before = _counters(profile)
        grant = host._authority.grants["reader"]
        host._authority.service.operator_revoke(grant, operator=operator)
        refused = False
        try:
            host.require_client(reader_client)
        except ValueError:
            refused = True
        cases.append({"id": "original_native_revocation", "passed": refused})
        host.request_shutdown(operator=operator)
        host.close()
        closed = False
        try:
            host.require_client(original)
        except ValueError:
            closed = True
        cases.append({"id": "shutdown_fences_original_client", "passed": closed})
    with ExitStack() as stack:
        host = ManagedToolHost(profile, operator=operator, policy_epoch=1, takeover=True)
        stack.callback(host.close)
        after = _counters(profile)
        retained = bool(before) and all(
            key in after and after[key][1] >= values[1] for key, values in before.items()
        )
        fenced = False
        try:
            host.require_client(original)
        except ValueError:
            fenced = True
        cases.append({"id": "epoch_restart_fences_original_handle", "passed": fenced})
        cases.append({"id": "durable_consumption_survives_epoch_restart", "passed": retained})
    return {
        "scope": "fixed_original_linux_host_transitions",
        "passed": all(case["passed"] for case in cases),
        "cases": cases,
        "duration_seconds": time.monotonic() - started,
        "fixture_input_sha256": hashlib.sha256(seed.read_bytes()).hexdigest(),
        "physical_boundary": "owned_linux_read_worker",
        "execution_authority": False,
    }
