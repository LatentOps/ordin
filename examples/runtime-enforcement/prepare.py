"""Emit an advisory demo policy from a real review; never start or apply a runtime."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "integrations/runtime")]
from ordin import ActionEnvelope, Ordin, derive_runtime_capability_contract
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin_runtime.compiler import OrdinRuntimeBackend
from ordin_runtime.model import serialize_policy


def main():
    filesystem = tuple(
        FilesystemCapability(access, path, "prefix")
        for path in (
            "/usr",
            "/lib",
            "/etc",
            "/app",
            "/var/log",
            "/proc",
            "/dev/urandom",
            "/readonly",
        )
        for access in ("read", "execute")
    ) + tuple(
        FilesystemCapability(access, path, "prefix")
        for path in ("/tmp", "/dev/null")
        for access in ("read", "write", "delete", "execute")
    )
    profile = RuntimeRequirementProfile(
        "openshell-demo-explicit-startup", filesystem, {"curl": "/usr/bin/curl"}, True
    )
    review = Ordin(runtime_requirements=profile).review_action(
        ActionEnvelope.shell(
            "curl --disable --request GET https://api.github.com/repos/LatentOps/ordin/issues/37",
            action_id="public-issue-get",
        )
    )
    result = OrdinRuntimeBackend((1000, 1000)).compile(derive_runtime_capability_contract(review))
    if result.status != "success" or result.plan is None:
        raise ValueError(result.reason_code)
    print(serialize_policy(result.plan.policy), end="")


if __name__ == "__main__":
    main()
