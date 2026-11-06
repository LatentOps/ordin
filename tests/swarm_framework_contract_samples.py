"""Framework JSON is inspectible data, never restored host authority."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integrations/swarm"))
from ordin_swarm.sdk import FrameworkPreparation, FrameworkResult
from ordin_swarm.adapters.contracts import coverage
from ordin_swarm.cli import setup, installation


def framework_contract_samples(tmp_path):
    h = "a" * 64
    return {
        "swarm_framework_fixture": {
            "schema_version": "ordin.swarm_framework_fixture.v1",
            "framework": "custom",
            "versions": {},
            "upstream_status": "host_owned",
            "trust_boundary": "host_owned_synthetic_fixture",
            "allowed_read_completed": True,
            "private_handoff_delivered": True,
            "inherited_labels": ["secret"],
            "source_flow_violated": True,
            "egress_callbacks": 0,
            "child_callbacks": 0,
            "denied_reviews": 2,
            "post_tool_outcome_linked": True,
            "physical_enforcement": False,
            "observed_exfiltration": "unknown",
            "execution_authority": False,
        },
        "swarm_framework_preparation": FrameworkPreparation(
            "deny", h, ("framework.unrepresented",)
        ).as_dict(),
        "swarm_framework_result": FrameworkResult("unknown", h, h, True, False).as_dict(),
        "swarm_framework_session": {
            "schema_version": "ordin.swarm_framework_session.v1",
            "context_digest": h,
            "tool_names": ["read_file"],
            "state": "connected",
            "mode": "intercept",
            "physical_enforcement": False,
            "execution_authority": False,
            "uncovered": ["unwrapped_direct_calls"],
        },
        "swarm_framework_adapter": coverage("custom"),
        "swarm_framework_installation": installation("custom"),
        "swarm_framework_setup": setup("custom", directory=tmp_path),
    }
