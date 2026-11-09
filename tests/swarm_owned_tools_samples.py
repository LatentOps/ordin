"""Reusable original backend/broker fixture; never fabricates approval or receipts."""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from ordin import ToolCallAdapter
from tests.test_swarm_broker import fixture, require_kernel


@dataclass
class OwnedConfiguration:
    broker: Any
    service: Any
    ledger: Any
    backend: Any
    read_action: Any
    channel: Any
    grant: str
    context: Any
    registry_channel: Any
    adapter: object
    clock: list
    operator: object
    rights: Any
    target: Any
    registry: Any
    bootstrap: Any
    details: dict

    def write_action(self, content="changed through owned route\n", *, action_id="owned-write"):
        current = self.backend.snapshot(str(self.target), operator=self.operator)
        return ToolCallAdapter("fixture").adapt(
            "write_artifact",
            {
                "path": str(self.target),
                "content": content,
                "expected_version": current["version"],
                "expected_digest": current["content_digest"],
            },
            action_id=action_id,
        )


@contextmanager
def configured(tmp_path, *, governance_bootstrap=False, physical=False, shared_clock=None):
    """Original TLS actors, real owned backend and full read/write root/child rights.

    Default writes naturally remain core WARN/requires approval. This helper
    grants no approval and never changes a core decision. Optional bootstrap is
    for the separately installed protected human-governance integration.
    """
    require_kernel()
    with fixture(
        tmp_path,
        owned_tools=True,
        physical=physical,
        shared_clock=shared_clock,
        approval_decision="warn" if governance_bootstrap else None,
    ) as values:
        yield OwnedConfiguration(*values)
