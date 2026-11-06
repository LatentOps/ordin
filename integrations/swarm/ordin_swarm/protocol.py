"""Non-Python runtimes use the maintained authenticated coordinator JSON wire."""

import ssl
from threading import RLock

from ordin.action import ActionEnvelope
from ordin.swarm.coordinator_rpc import CoordinatorClient


class FrameworkJSONClient:
    """No reconnect, retry, JSON-selected identity or executable callback."""

    def __init__(self, connection: ssl.SSLSocket):
        self._client = CoordinatorClient(connection)
        self._lock = RLock()

    def request(self, operation, **arguments):
        with self._lock:
            return self._client.request(operation, **arguments)

    def prepare(self, *, lease, grant, action: ActionEnvelope, idempotency_key):
        if type(action) is not ActionEnvelope or action.action_id is None:
            raise ValueError("exact typed framework action required")
        evaluation = self.request(
            "evaluate",
            lease=lease,
            grant=grant,
            action=action.as_dict(),
            idempotency_key=idempotency_key,
        )
        if evaluation["status"] != "execute":
            return evaluation
        return self.request(
            "reserve",
            lease=lease,
            evaluation=evaluation["reference"],
            action=action.as_dict(),
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def contract():
        return {
            "request_schema": "swarm_coordinator_request",
            "response_schema": "swarm_coordinator_response",
            "frame": "uint32_be_length_then_utf8_json",
            "maximum_frame_bytes": 65536,
            "deadline_seconds": 10,
            "authentication": "mutual_tls_pinned_server_scope",
            "identity_source": "original_authenticated_workload_or_broker_enrollment",
            "retries": False,
            "callbacks_over_wire": False,
            "json_execution_authority": False,
        }


__all__ = ["FrameworkJSONClient"]
