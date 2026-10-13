"""Packaged wholly synthetic offline examples. No proposed action is executed."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ordin import (
    ActionEnvelope,
    AgentGate,
    Ordin,
    ReviewPolicy,
    ToolCallAdapter,
    ToolSemanticRule,
    ToolResourceBinding,
    ToolSemanticsRegistry,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource

from .models import RepositoryScope, SecurityProfile, SecurityInvariant, InvariantSelectors
from .profiles import ProtectedProfileSelection, load_approved_profile
from .host import HostEvidenceSource
from .gate import AssuranceGate
from .attack_paths import ReviewedAction, build_attack_path
from .simulation import SimulationPolicy, FrozenCase, FrozenCorpus, simulate_policy_change
from .challenge import challenge_authority_subset, replay_counterexample
from .delegation import DelegationAuthority, verify_delegation_subset
from .codex_security.workflow import WorkflowCapture, WorkflowImportScope, import_workflow_claims
from .codex_security import ImportScope, import_sarif
from .offline import inspect_profile_content, preview_invariants


def run_quickstart():
    semantics = ToolSemanticsRegistry(
        "synthetic-tools",
        "1",
        (
            ToolSemanticRule(
                "read",
                "tool",
                "read_file",
                ("filesystem.read",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
            ToolSemanticRule(
                "write",
                "tool",
                "write_file",
                ("filesystem.write",),
                runtime="fixture",
                resources=(ToolResourceBinding("path", "path"),),
            ),
        ),
    )
    adapter = ToolCallAdapter("fixture")
    read = adapter.adapt(
        "read_file", {"path": "/synthetic/project/readme"}, action_id="synthetic-read"
    )
    write = adapter.adapt(
        "write_file", {"path": "/synthetic/project/cache"}, action_id="synthetic-write"
    )
    core = Ordin(tool_semantics=semantics)
    repo = RepositoryScope("fixture/quickstart", "snapshot-1")
    profile = SecurityProfile(
        "synthetic-profile",
        "1",
        repo,
        invariants=(
            SecurityInvariant(
                "no-network",
                "forbid_effect",
                InvariantSelectors(effects=("network.connect",)),
                on_violation="block",
            ),
        ),
    )
    with tempfile.TemporaryDirectory(prefix="ordin-assurance-quickstart-") as name:
        root = Path(name).resolve(strict=True)
        protected = root / "protected"
        protected.mkdir(mode=0o700)
        profile_path = protected / "profile.json"
        profile_path.write_bytes(json.dumps(profile.as_dict()).encode())
        profile_path.chmod(0o600)
        runtime_policy = "a" * 64
        selection = ProtectedProfileSelection(
            protected.resolve(),
            "profile.json",
            "/operator/profile.json",
            repo,
            profile.digest,
            hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            profile.version,
            "synthetic-operator",
            RuntimeCapabilityBoundary(
                "synthetic-agent",
                filesystem=(FilesystemCapability("write", "/synthetic", "prefix"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            ),
            RuntimeEvidenceSource("synthetic-host", "b" * 64, "synthetic-sandbox", runtime_policy),
        )
        approved = load_approved_profile(
            selection, current_repository=repo, active_runtime_policy_digest=runtime_policy
        )
        source = HostEvidenceSource(
            "synthetic-agent", repo, "b" * 64, 1, runtime_policy, selection.digest
        )
        host = source.context()
        gate = AssuranceGate(AgentGate(core), approved)
        safe = gate.evaluate_action(read, host_context=host)
        network = gate.evaluate_action(
            ActionEnvelope.shell(
                "curl https://example.invalid/status", action_id="synthetic-network"
            ),
            host_context=host,
        )
        graph = build_attack_path(source, (ReviewedAction(network, host),))
        corpus = FrozenCorpus.synthetic(
            (
                FrozenCase("benign", read, expected="execute", label="benign"),
                FrozenCase(
                    "write-boundary", write, expected="escalate", label="adversarial", critical=True
                ),
            )
        )
        simulation = simulate_policy_change(
            SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=semantics)),
            SimulationPolicy(core),
            corpus,
            baseline_revision="synthetic-before",
            candidate_revision="synthetic-after",
        )
        discovered = challenge_authority_subset(
            seed=42, revision="synthetic-v1", trials=16, variant="seeded_prefix_bug"
        )
        replayed = [
            replay_counterexample(item, expected_revision="synthetic-v1")
            for item in discovered.counterexamples
        ]
        maximum = DelegationAuthority(
            RuntimeCapabilityBoundary(
                "declared-max",
                filesystem=(FilesystemCapability("read", "/synthetic/project/readme"),),
            )
        )
        delegation = verify_delegation_subset(maximum, maximum, maximum, maximum)
        workflow_root = root / "saved-workflow"
        workflow_root.mkdir(mode=0o700)
        raw = json.dumps(
            {
                "repository": "synthetic-repo",
                "scanId": "synthetic-scan",
                "results": [
                    {
                        "id": "synthetic-occurrence",
                        "status": "fixed",
                        "evidence": "Synthetic external reported tests",
                    }
                ],
            }
        ).encode()
        (workflow_root / "workflow.json").write_bytes(raw)
        capture = WorkflowCapture(
            "verify_fix",
            repo,
            {"name": "codex-security", "version": "0.2.0"},
            "synthetic-scan",
            "synthetic-repo",
            ("synthetic-occurrence",),
            hashlib.sha256(raw).hexdigest(),
            0,
            "completed",
            None,
        )
        (workflow_root / "workflow-capture.json").write_bytes(
            json.dumps(capture.as_dict()).encode()
        )
        imported = import_workflow_claims(
            WorkflowImportScope(
                workflow_root,
                repo,
                "verify_fix",
                expected_scan_id="synthetic-scan",
                expected_identifiers=("synthetic-occurrence",),
            )
        )
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Codex Security"}},
                    "results": [
                        {
                            "ruleId": "synthetic-boundary",
                            "message": {"text": "Synthetic unverified candidate"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "synthetic_guard.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        (workflow_root / "results.sarif").write_bytes(json.dumps(sarif).encode())
        vulnerability_import = import_sarif(ImportScope(workflow_root, repo))
        return {
            "schema_version": "ordin.assurance_offline_quickstart.v1",
            "synthetic_only": True,
            "actions_executed": False,
            "model_or_scanner_called": False,
            "policy_installed": False,
            "profile_content": inspect_profile_content(profile),
            "invariant_preview": preview_invariants(
                profile, ActionEnvelope.shell("curl https://example.invalid/status")
            ),
            "protected_profile_demo": {
                "safe_disposition": safe.disposition,
                "network_disposition": network.disposition,
                "profile_digest": approved.digest,
                "host_selection_digest": selection.digest,
            },
            "simulation": {
                "report_digest": simulation.digest,
                "authority_delta": simulation.policy_authority_delta,
                "newly_escalated": list(simulation.newly_escalated),
                "critical_misses": simulation.critical_misses,
            },
            "challenge": {
                "seed": 42,
                "failures": discovered.failures,
                "replayed": replayed,
                "injected_defect": True,
                "real_ordin_vulnerability_claimed": False,
            },
            "attack_path": {
                "graph_digest": graph.digest,
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "reachability": graph.reachability,
                "exposure": graph.exposure,
                "runtime_observations": 0,
            },
            "delegation": {
                "result": delegation.result,
                "verification_digest": delegation.digest,
                "grant_issued": False,
            },
            "external_claims": imported.public_dict(),
            "offline_finding_import": vulnerability_import.public_dict(),
            "limitations": [
                "Owned synthetic fixtures and protected host declarations only; no OS enforcement, real exploit or broad security effectiveness is established.",
                "Optional local model shadow is a separate installed example; real setup/inference requires explicit protected consent.",
            ],
        }


def main():
    print(json.dumps(run_quickstart(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
