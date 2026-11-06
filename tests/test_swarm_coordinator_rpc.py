"""Real mTLS frames, role separation and exact online references."""

from concurrent.futures import ThreadPoolExecutor
import json
import struct

import pytest

from ordin.swarm.coordinator_rpc import CoordinatorClient, CoordinatorEndpoint
from ordin.swarm.coordinator_store import CoordinatorRejected
from tests.assurance.test_delegating_gate import action
from tests.test_swarm_coordinator import configured


def rpc(endpoint, server, client, operation, **arguments):
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(endpoint.serve_one, server)
        result = CoordinatorClient(client).request(operation, **arguments)
        pending.result(timeout=10)
        return result


def test_real_tls_round_trip_policy_reservation_and_one_use_online_refs(tmp_path):
    with configured(tmp_path) as data:
        endpoint = CoordinatorEndpoint(data["coordinator"], data["scope"])
        server, client = data["sockets"]["child"]
        lease = data["leases"]["child"].reference
        policy = rpc(endpoint, server, client, "policy", lease=lease)
        assert policy["policy_epoch"] == 0 and not policy["execution_authority"]
        proposed = action("rpc")
        evaluation = rpc(
            endpoint,
            server,
            client,
            "evaluate",
            lease=lease,
            grant=data["references"]["child"],
            action=proposed.as_dict(),
            idempotency_key="rpc-evaluate",
        )
        reservation = rpc(
            endpoint,
            server,
            client,
            "reserve",
            lease=lease,
            evaluation=evaluation["reference"],
            action=proposed.as_dict(),
            idempotency_key="rpc-reserve",
        )
        assert reservation["status"] == "reserved" and not reservation["execution_authority"]
        with pytest.raises(CoordinatorRejected):
            rpc(endpoint, server, client, "forward", reservation=reservation["reference"])
        assert rpc(
            endpoint, server, client, "cancel", lease=lease, reservation=reservation["reference"]
        )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":"ordin.swarm_coordinator_request.v1","operation":"admit","arguments":{},"role":"broker"}',
        b'{"schema_version":"ordin.swarm_coordinator_request.v1","operation":"admit","operation":"forward","arguments":{}}',
        b'{"schema_version":"ordin.swarm_coordinator_request.v1","operation":"record_fence","arguments":{}}',
    ],
)
def test_wire_roles_duplicate_keys_and_control_methods_cannot_mint_authority(tmp_path, payload):
    with configured(tmp_path) as data:
        endpoint = CoordinatorEndpoint(data["coordinator"], data["scope"])
        server, client = data["sockets"]["child"]
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(endpoint.serve_one, server)
            client.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", client.recv(4))[0]
            response = bytearray()
            while len(response) < length:
                response.extend(client.recv(length - len(response)))
            result = json.loads(response)
            pending.result(timeout=10)
        assert result["status"] == "denied" and not result["execution_authority"]


def test_client_refuses_non_tls_or_nonverified_socket():
    with pytest.raises(ValueError):
        CoordinatorClient(object())
