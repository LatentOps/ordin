"""Synthetic finding-to-policy-fix example; no reviewed action or target code runs."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ordin import (
    Ordin,
    ReviewPolicy,
    ToolCallAdapter,
    ToolSemanticRule,
    ToolResourceBinding,
    ToolSemanticsRegistry,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability

from .host import HostEvidenceSource
from .inventory import AuthorizedRepository
from .models import RepositoryScope, SourceReference, SecurityFinding
from .validation_models import FindingRubric
from .validation import review_finding, load_replay_fixture, validate_finding_replay, close_finding
from .remediation import propose_remediation, verify_fix
from .simulation import SimulationPolicy
from .source_patch import propose_source_patch


def run_demo():
    semantics = ToolSemanticsRegistry(
        "synthetic-files",
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
    reproduction = adapter.adapt(
        "write_file", {"path": "/fixture/outside-task"}, action_id="reproduce"
    )
    benign = adapter.adapt("read_file", {"path": "/fixture/allowed.txt"}, action_id="benign")
    boundary = RuntimeCapabilityBoundary(
        "expected-task-bound",
        filesystem=(FilesystemCapability("read", "/fixture/allowed.txt"),),
        tools=(ToolCapability("fixture", None, "read_file"),),
    )
    old = SimulationPolicy(Ordin(policy=ReviewPolicy("block"), tool_semantics=semantics))
    new = SimulationPolicy(Ordin(tool_semantics=semantics))
    # Temporary synthetic files are the whole test scope. No caller repository
    # source is imported, executed or changed; no private traces are persisted.
    with tempfile.TemporaryDirectory(prefix="ordin-finding-demo-") as directory:
        rows = []
        for revision in ("before-v1", "after-v2"):
            root = Path(directory).resolve(strict=True) / revision
            root.mkdir()
            (root / "config.py").write_text(
                "# Synthetic policy configuration reference only.\n", encoding="utf-8"
            )
            scope = AuthorizedRepository(
                root.resolve(), RepositoryScope("fixture/validation-demo", revision), "/fixture"
            )
            source = HostEvidenceSource(
                "fixture-agent", scope.repository, "a" * 64, 1, "b" * 64, "c" * 64
            )

            def reference(path):
                return SourceReference(
                    path, 1, revision, hashlib.sha256((root / path).read_bytes()).hexdigest()
                )

            selected = []
            for action in (reproduction, benign):
                assert action.action_id is not None
                packet = {
                    "schema_version": "ordin.assurance_replay_input.v1",
                    "case_id": action.action_id,
                    "action": action.as_dict(),
                }
                path = action.action_id + ".json"
                (root / path).write_text(json.dumps(packet), encoding="utf-8")
                selected.append(load_replay_fixture(scope, reference(path)))
            code = reference("config.py")
            candidate = SecurityFinding(
                "synthetic-candidate",
                "gate_authority_subset",
                scope.repository,
                "d" * 64,
                affected_sources=(code,),
                invariant_id="task.authority_subset",
                origin="imported_claim",
                status="imported",
            )
            rubric = FindingRubric(
                source.principal,
                (code,),
                ("filesystem.read",),
                "task.authority_subset",
                boundary.digest,
                (code,),
                changes=("Synthetic gate configuration test only.",),
            )
            review = review_finding(scope, candidate, rubric)
            rows.append((scope, source, candidate, review, *selected))
        before, after = rows
        validation = validate_finding_replay(
            before[0], before[1], before[2], before[3], before[4], old.build_gate(), boundary
        )
        closed = close_finding(before[0], before[1], before[2], before[3], validation)
        proposal = propose_remediation(validation, old, new, after[0].repository)
        verified = verify_fix(
            proposal,
            validation,
            before_scope=before[0],
            before_source=before[1],
            before_finding=before[2],
            before_review=before[3],
            after_scope=after[0],
            after_source=after[1],
            after_finding=after[2],
            after_review=after[3],
            reproduction=(before[4], after[4]),
            benign_controls=((before[5], after[5]),),
            boundary=boundary,
        )
        patch = propose_source_patch(
            before[0],
            validation,
            before[2].affected_sources[0],
            "# Proposed private code change; not executed.\n",
        )
        return {
            "schema_version": "ordin.assurance_validation_demo.v1",
            "synthetic_only": True,
            "actions_executed": False,
            "target_code_executed": False,
            "patch_applied": False,
            "review": before[3].public_dict(),
            "validation": validation.public_dict(),
            "closure": {
                "status": closed.status,
                "verification_scope": closed.verification_scope,
                "validation_digest": closed.validation_digest,
            },
            "policy_proposal": proposal.public_dict(),
            "fix": verified.public_dict(),
            "source_patch": patch.public_dict(),
            "limitations": [
                "Synthetic gate/policy replay only; no target-code fix, real exploit, host sandbox or release acceptance is established."
            ],
        }


def main():
    print(json.dumps(run_demo(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
