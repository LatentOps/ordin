"""Verify an explicitly supplied local wheel in a fresh workspace-only venv.

Uses local pip with --no-index/--no-deps, launches no reviewed action and
performs no scanner/model/provider setup. Refuses to reuse an existing venv.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import venv
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SMOKE = r"""
import json, socket
import subprocess
def refuse_network(*args, **kwargs):
    raise AssertionError("default assurance attempted network access")
class NoNetworkSocket(socket.socket):
    def __new__(cls, *args, **kwargs):
        return refuse_network(*args, **kwargs)
socket.create_connection = refuse_network
socket.socket = NoNetworkSocket
def refuse_process(*args, **kwargs):
    raise AssertionError("default assurance attempted subprocess execution")
subprocess.Popen = refuse_process
import ordin
import ordin.assurance as assurance
import importlib, pkgutil
from pathlib import Path
from ordin.assurance.examples import run_examples
# Import every shipped Assurance module and execute every standalone example.
# The existing spies cover imports, argv parsing and fixture execution together.
public_modules = sorted(info.name for info in pkgutil.walk_packages(assurance.__path__, assurance.__name__ + "."))
for name in public_modules:
    importlib.import_module(name)
standalone_examples = run_examples(scratch_root=Path.cwd())
assert standalone_examples["example_count"] == 8 and standalone_examples["all_passed"] is True
from ordin.assurance.solver import challenge_capability_intersection
solver_disabled = challenge_capability_intersection(revision="wheel-fixture-v1")
assert solver_disabled.solver_result == "unavailable" and solver_disabled.conclusion == "inconclusive"
from ordin.schema import SCHEMA_FILES, validate_schema_files, resource_parity_errors
from ordin.assurance._schemas import SCHEMAS
from ordin.assurance import SecurityProfile, RepositoryScope, ModelAnswer
from ordin import ActionEnvelope, AgentGate
from ordin.assurance import FrozenCase, FrozenCorpus, SimulationPolicy, simulate_policy_change
from ordin.assurance.cli import main as assure_cli
assert all(name in SCHEMA_FILES for name in SCHEMAS)
assert validate_schema_files() == []
assert resource_parity_errors() == []
profile = SecurityProfile("fixture", "1", RepositoryScope("fixture/repo", "snapshot-1"))
assert SecurityProfile.from_json(json.dumps(profile.as_dict())) == profile
assert AgentGate().evaluate_action(ActionEnvelope.shell("git status --short")).disposition == "execute"
assert AgentGate().evaluate_action(ActionEnvelope.shell("rm -rf /")).disposition == "deny"
assert ModelAnswer("risk", 0.5).p_yes == 0.5
from ordin.assurance.validation_demo import run_demo as validation_demo
finding_demo = validation_demo()
assert finding_demo["actions_executed"] is False and finding_demo["target_code_executed"] is False
assert finding_demo["patch_applied"] is False
assert finding_demo["validation"]["result"] == "confirmed"
assert finding_demo["validation"]["tested_scope"] == "gate_authority_subset"
assert finding_demo["fix"]["result"] == "fixed-verified" and finding_demo["fix"]["integrated"] is False
from ordin.assurance.regression_demo import run_demo as regression_demo
regression_example = regression_demo(scratch_root=Path.cwd())
assert regression_example["synthetic_review_only"] and regression_example["case_reviewed"]
assert regression_example["failure_and_benign_replayed"] and regression_example["duplicate_refused"]
assert not any(regression_example[key] for key in ("actions_executed", "target_code_executed", "live_corpus_or_policy_changed", "host_boundary_exercised", "artifacts_retained"))
from ordin.assurance.quickstart import run_quickstart
quickstart = run_quickstart()
assert quickstart["actions_executed"] is False and quickstart["model_or_scanner_called"] is False
assert quickstart["protected_profile_demo"]["safe_disposition"] == "execute"
assert quickstart["protected_profile_demo"]["network_disposition"] == "deny"
assert quickstart["offline_finding_import"]["finding_count"] == 1
assert quickstart["offline_finding_import"]["finding_confirmation"] == "not_performed"
from ordin.assurance.rest_demo import run_demo as rest_demo
rest_example = rest_demo()
assert rest_example["default_disposition"] == "escalate"
assert rest_example["selected_disposition"] == "execute"
assert rest_example["network_called"] is False and rest_example["actions_executed"] is False
assert all(row["disposition"] == "deny" and not row["old_binding_matches"] for row in rest_example["changes"])
from ordin.assurance.codex_security import WorkflowCapture, WorkflowImportScope, import_workflow_claims
from ordin.assurance import (SyntheticPathCase, SyntheticPathSuite, VettedSandboxRuntime,
                             load_vetted_program, load_synthetic_suite, run_sandbox_test)
import tempfile, threading, hashlib, sys, contextlib, io
from pathlib import Path
with tempfile.TemporaryDirectory(prefix="ordin-vetted-noexec-") as directory:
    root = Path(directory)
    repo = RepositoryScope("fixture/vetted-wheel", "snapshot-1")
    selected_scope = assurance.AuthorizedRepository(root, repo, "/fixture")
    (root / "guard.py").write_bytes(b"def within_root(path, root):\n    return path.startswith(root)\n")
    test_suite = SyntheticPathSuite("vetted-wheel", (
        SyntheticPathCase("benign", "/synthetic/project/file", "/synthetic/project"),
        SyntheticPathCase("collision", "/synthetic/project-other", "/synthetic/project")))
    (root / "suite.json").write_bytes(json.dumps(test_suite.as_dict()).encode())
    def source_ref(name):
        return assurance.SourceReference(name, 1, repo.revision, hashlib.sha256((root / name).read_bytes()).hexdigest())
    vetted = load_vetted_program(selected_scope, source_ref("guard.py"))
    test_inputs = load_synthetic_suite(selected_scope, source_ref("suite.json"))
    source = assurance.HostEvidenceSource("fixture-agent", repo, "a" * 64, 1, "b" * 64, "c" * 64)
    worker = Path(assurance.__file__).parent / "_sandbox_worker.py"
    selected_runtime = VettedSandboxRuntime(Path(sys.executable), "a" * 64, worker, "b" * 64,
        (str(worker),), root, root, "c" * 64, (root,))
    precanceled = threading.Event(); precanceled.set()
    noexec = run_sandbox_test(selected_scope, source, selected_runtime, vetted, test_inputs, None, cancel=precanceled)
    assert noexec.status == "canceled" and noexec.results == ()
with tempfile.TemporaryDirectory(prefix="ordin-workflow-offline-") as directory:
    workflow_root = Path(directory)
    workflow_repo = RepositoryScope("fixture/workflow-wheel", "snapshot-1")
    raw = json.dumps({"repository":"fixture-worker","scanId":"scan-wheel",
        "results":[{"id":"occ-wheel","status":"fixed","evidence":"Synthetic claimed verification"}]}).encode()
    (workflow_root / "workflow.json").write_bytes(raw)
    capture = WorkflowCapture("verify_fix",workflow_repo,{"name":"codex-security","version":"0.2.0"},
        "scan-wheel","fixture-worker",("occ-wheel",),hashlib.sha256(raw).hexdigest(),0,"completed",None)
    (workflow_root / "workflow-capture.json").write_bytes(json.dumps(capture.as_dict()).encode())
    claims = import_workflow_claims(WorkflowImportScope(workflow_root,workflow_repo,"verify_fix",
        expected_scan_id="scan-wheel",expected_identifiers=("occ-wheel",)))
    assert claims.completeness == "complete" and claims.closure == "not_performed"
    assert claims.claims[0].reported_verdict == "fixed" and claims.claims[0].status == "imported"
    with contextlib.redirect_stdout(io.StringIO()) as stream:
        assert assure_cli(["codex","import-workflow","--artifact-root",str(workflow_root),
            "--repository",workflow_repo.id,"--revision",workflow_repo.revision,"--workflow","verify_fix",
            "--expected-scan-id","scan-wheel","--expected-identifier","occ-wheel"]) == 0
    assert "Synthetic claimed verification" not in stream.getvalue()
corpus = FrozenCorpus.synthetic((FrozenCase("wheel-safe", ActionEnvelope.shell("git status --short"),
                                          expected="execute", label="benign"),))
simulation = simulate_policy_change(SimulationPolicy(), SimulationPolicy(), corpus,
                                   baseline_revision="wheel-fixture-v1", candidate_revision="wheel-fixture-v1")
assert simulation.activation_safe and simulation.cases[0].candidate_final == "execute"
from ordin.assurance import challenge_authority_subset, replay_counterexample
challenged = challenge_authority_subset(seed=14, revision="wheel-fixture-v1", trials=16,
                                        variant="seeded_prefix_bug")
assert challenged.failures == 4 and challenged.benign_controls == 4
assert all(replay_counterexample(record, expected_revision="wheel-fixture-v1") == "verified_failure"
           for record in challenged.counterexamples)
from ordin.assurance import challenge_property, ChallengeRun
request_checks = challenge_property(property_id="exact_request_commitment", seed=14,
                                   revision="wheel-fixture-v1", trials=16)
assert request_checks.status == "passed" and request_checks.failures == 0
assert ChallengeRun.from_json(json.dumps(request_checks.as_dict())) == request_checks
seeded_requests = challenge_property(property_id="exact_request_commitment", seed=14,
                                    revision="wheel-fixture-v1", trials=16, variant="seeded_unsafe_checker")
assert seeded_requests.failures == 12
assert all(replay_counterexample(record, expected_revision="wheel-fixture-v1") == "verified_failure"
           for record in seeded_requests.counterexamples)
from ordin.assurance import HostEvidenceSource, register_instruction_origin, correlate_source_use, verify_source_use
host_source = HostEvidenceSource("fixture-agent", RepositoryScope("fixture/wheel", "snapshot-1"),
                                 "a" * 64, 1, "b" * 64, "c" * 64)
origin = register_instruction_origin(host_source, origin_id="wheel-origin", kind="mcp_result",
                                     classification="public", content="synthetic wheel data")
source_action = ActionEnvelope("tool", "call", {"body": "synthetic wheel data"})
source_use = correlate_source_use(host_source, origin, source_action, use_id="wheel-use",
                                 argument_path=("parameters", "body"))
assert verify_source_use(host_source, origin, source_use, source_action)
from ordin.assurance import AssuranceGate, ReviewedAction, build_attack_path, record_source_provenance
context = host_source.context()
graph_decision = AssuranceGate().evaluate_action(ActionEnvelope.shell("git status --short", action_id="graph-action"),
                                                host_context=context)
path = build_attack_path(host_source, (ReviewedAction(graph_decision, context),))
assert path.reachability == "hypothesis" and path.proof_gaps
provenance = record_source_provenance(host_source, source_action, origins=(origin,), uses=(source_use,))
assert provenance.completeness == "partial"
from ordin.assurance import DelegationAuthority, DelegationIssuer, DelegatingAssuranceGate, ProtectedProfileSelection, load_approved_profile
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin import Ordin, ToolCallAdapter, ToolSemanticRule, ToolResourceBinding, ToolSemanticsRegistry
from pathlib import Path
from dataclasses import replace
import hashlib
protected = Path.cwd() / "wheel-delegation-profile"
protected.mkdir(mode=0o700)
protected_file = protected / "profile.json"
protected_file.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
protected_file.chmod(0o600)
selection = ProtectedProfileSelection(protected.resolve(), "profile.json", "/operator/profile.json", profile.repository,
    profile.digest, hashlib.sha256(protected_file.read_bytes()).hexdigest(), "1", "fixture-operator",
    RuntimeCapabilityBoundary("fixture-protection", filesystem=(FilesystemCapability("read", "/fixture", "prefix"),),
        filesystem_semantics="lexical_prefix", runtime_filesystem_guarantees=True),
    RuntimeEvidenceSource("fixture", "a" * 64, "fixture-sandbox", "b" * 64))
approved = load_approved_profile(selection, current_repository=profile.repository, active_runtime_policy_digest="b" * 64)
parent_source = HostEvidenceSource("parent", profile.repository, "a" * 64, 0, "b" * 64, selection.digest)
child_source = replace(parent_source, principal="child", session_digest="d" * 64)
authority = DelegationAuthority(RuntimeCapabilityBoundary("fixture-authority", filesystem=(FilesystemCapability("read", "/fixture/source", "exact"),),
    tools=(ToolCapability("fixture", None, "read_file"),)))
issuer = DelegationIssuer(parent_source, approved, authority, authority, clock=lambda: 100)
root = issuer.authorize_root(authority, grant_id="root", expires_at=200)
child = issuer.issue_child(root, child_source, authority, grant_id="child", expires_at=150)
semantics = ToolSemanticsRegistry("fixture-tools", "1", (ToolSemanticRule("read", "tool", "read_file", ("filesystem.read",),
    runtime="fixture", resources=(ToolResourceBinding("path", "path"),)),))
delegating = DelegatingAssuranceGate(AssuranceGate(AgentGate(Ordin(tool_semantics=semantics)), approved), issuer, child, child_source)
adapter = ToolCallAdapter("fixture")
delegated_read = delegating.evaluate_action(adapter.adapt("read_file", {"path": "/fixture/source"}, action_id="delegated-read"))
assert delegated_read.may_execute
issuer.revoke(root)
assert not delegating.commit_use(delegated_read, delegated_read.assurance.review.action)
from ordin.assurance.codex_security import ImportScope, import_codex_json, import_sarif
scan_root = Path.cwd() / "wheel-saved-scan"
scan_root.mkdir()
from ordin.assurance.codex_security.scanner import mock_scanner_run
from ordin.assurance.diff_triage import triage_source_diff
from ordin.assurance import AuthorizedRepository
assert mock_scanner_run(exit_code=1).status == "severity_violation"
diff_scope = AuthorizedRepository(scan_root.resolve(), RepositoryScope("fixture/wheel-diff", "snapshot-1"), "/fixture")
diff_report = triage_source_diff(diff_scope, diff_scope)
assert diff_report.advisory_only and not diff_report.review_required
scan_findings = {"documentType":"codex-security.findings","schemaVersion":"1.0","scanId":"wheel-scan","findings":[]}
scan_coverage = {"documentType":"codex-security.coverage","schemaVersion":"1.0","scanId":"wheel-scan","mode":"repository",
    "completeness":"partial","inventoryStrategy":"repository","includePaths":["."],"excludePaths":[],"surfaces":[],"explicitExclusions":[],
    "deferred":[{"id":"pending","reason":"Synthetic incomplete scan."}]}
scan_manifest = {"documentType":"codex-security.scan-manifest","schemaVersion":"1.0","scan":{"id":"wheel-scan",
    "producer":{"name":"codex-security-plugin","version":"0.1.0"},"status":"completed","startedAt":"2026-10-10T00:00:00Z",
    "completedAt":"2026-10-10T00:01:00Z","sealedAt":"2026-10-10T00:01:00Z","target":{"kind":"git_revision","targetId":"fixture-target",
    "displayName":"fixture/repo","revision":"snapshot-1"},"scope":{"includePaths":["."],"excludePaths":[]},"coverageRef":"coverage.json",
    "findingsRef":"findings.json","artifacts":[]}}
for name,packet in (("findings.json",scan_findings),("coverage.json",scan_coverage)):
    raw = (json.dumps(packet)+"\n").encode()
    (scan_root/name).write_bytes(raw)
    scan_manifest["scan"]["artifacts"].append({"path":name,"sha256":hashlib.sha256(raw).hexdigest(),"mediaType":"application/json"})
(scan_root/"scan-manifest.json").write_bytes(json.dumps(scan_manifest).encode())
imported = import_codex_json(ImportScope(scan_root.resolve(),RepositoryScope("fixture/repo","snapshot-1")))
assert imported.completeness == "partial" and not imported.conclusive_import and imported.findings == ()
(scan_root/"results.sarif").write_bytes(json.dumps({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Codex Security"}},"results":[]}]}).encode())
assert import_sarif(ImportScope(scan_root.resolve(),RepositoryScope("fixture/repo","snapshot-1"))).completeness == "unknown"
import contextlib, io
from pathlib import Path
Path("wheel-profile.json").write_text(json.dumps(profile.as_dict()), encoding="utf-8")
with contextlib.redirect_stdout(io.StringIO()):
    assert assure_cli(["profile", "validate", "wheel-profile.json"]) == 0
import importlib.metadata
assert any(ep.name == "ordin-assure" for ep in importlib.metadata.distribution("ordin").entry_points)
from pathlib import Path
from ordin.assurance import AuthorizedRepository, build_threat_model, inventory_repository
fixture = Path.cwd() / "wheel-fixture-source"
fixture.mkdir()
(fixture / "main.py").write_text("def main():\n    pass\n", encoding="utf-8")
scope = AuthorizedRepository(fixture.resolve(), RepositoryScope("fixture/wheel", "snapshot-1"), "/fixture/wheel")
inventory = inventory_repository(scope)
assert len(inventory.files) == 1 and inventory.facts[0].source.symbol == "main"
assert build_threat_model(scope, inventory).draft.authoritative is False
print(json.dumps({"ok": True, "version": ordin.__version__, "schemas": len(SCHEMA_FILES),
                  "assurance_schemas": len(SCHEMAS), "exports": sorted(assurance.__all__),
                  "finding_validation_demo": finding_demo,
                  "boundary_regression_demo": regression_example,
                  "vetted_test_no_execution": True,
                  "offline_workflow_claims": True,
                  "offline_quickstart": quickstart,
                  "rest_example": rest_example,
                  "assurance_modules_imported": public_modules,
                  "standalone_examples": standalone_examples,
                  "optional_solver_unavailable": solver_disabled.as_dict(),
                  "loaded_from": ordin.__file__}))
"""


def run(wheel: Path, environment: Path) -> dict:
    wheel = wheel.resolve(strict=True)
    environment = environment.absolute()
    if not environment.resolve().is_relative_to(ROOT) or environment == ROOT:
        raise ValueError("wheel verification venv must be inside this workspace")
    if environment.exists():
        raise FileExistsError("wheel verification requires a new venv")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        required = {
            "ordin/assurance/__init__.py",
            "ordin/assurance/models.py",
            "ordin/assurance/_json.py",
            "ordin/assurance/_schemas.py",
            "ordin/assurance/simulation.py",
            "ordin/assurance/cli.py",
            "ordin/assurance/challenge.py",
            "ordin/assurance/_environment.py",
            "ordin/assurance/property_challenge.py",
            "ordin/assurance/_property_challenges.py",
            "ordin/assurance/requests.py",
            "ordin/assurance/origins.py",
            "ordin/assurance/attack_paths.py",
            "ordin/assurance/source_flow.py",
            "ordin/assurance/delegation.py",
            "ordin/assurance/delegating_gate.py",
            "ordin/assurance/delegated_paths.py",
            "ordin/assurance/codex_security/importer.py",
            "ordin/assurance/codex_security/sarif.py",
            "ordin/assurance/codex_security/_validation.py",
            "ordin/assurance/codex_security/scanner.py",
            "ordin/assurance/codex_security/_process_tree.py",
            "ordin/assurance/diff_triage.py",
            "ordin/assurance/examples/__init__.py",
            "ordin/assurance/examples/__main__.py",
            "ordin/resources/codex_security/findings.schema.json",
        }
        if not required <= names:
            raise ValueError("wheel is missing assurance modules")
        # A hand-written list alone cannot catch newly added modules/resources
        # omitted from explicit package enumeration. Compare the entire package.
        source_files = {}
        for source in (ROOT / "ordin").rglob("*"):
            if source.suffix not in {".py", ".json"}:
                continue
            relative = source.relative_to(ROOT).as_posix()
            raw = source.read_bytes()
            if relative not in names or archive.read(relative) != raw:
                raise ValueError("wheel is missing or differs from a current module/resource")
            source_files[relative] = hashlib.sha256(raw).hexdigest()
        wheel_sources = {
            name
            for name in names
            if name.startswith("ordin/") and Path(name).suffix in {".py", ".json"}
        }
        if wheel_sources != set(source_files):
            raise ValueError("wheel includes stale or unexpected package modules/resources")
        metadata = archive.read(next(name for name in names if name.endswith("/METADATA"))).decode()
        if any(
            line.startswith("Requires-Dist:") and "extra ==" not in line
            for line in metadata.splitlines()
        ):
            raise ValueError("wheel added a mandatory dependency")
    environment.mkdir(mode=0o700, parents=True, exist_ok=False)
    venv.EnvBuilder(with_pip=False).create(environment)
    interpreter = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    command = [
        sys.executable,
        "-m",
        "pip",
        "--python",
        str(interpreter),
        "install",
        "--no-index",
        "--no-deps",
        str(wheel),
    ]
    subprocess.run(
        command, cwd=environment, check=True, capture_output=True, text=True, timeout=120
    )
    result = subprocess.run(
        [str(interpreter), "-I", "-c", SMOKE],
        cwd=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env={
            **os.environ,
            "TEMP": str(environment),
            "TMP": str(environment),
            "TMPDIR": str(environment),
        },
    )
    if result.returncode:
        diagnostics = environment / "smoke-private-stderr.txt"
        with diagnostics.open("x", encoding="utf-8") as output:
            output.write(result.stderr[:65536])
        diagnostics.chmod(0o600)
        raise ValueError("installed wheel smoke failed; see its private stderr diagnostics")
    smoke = json.loads(result.stdout)
    if not Path(smoke["loaded_from"]).resolve().is_relative_to(environment.resolve()):
        raise ValueError("wheel smoke imported the source checkout")
    del smoke["loaded_from"]
    doctor = subprocess.run(
        [str(interpreter), "-I", "-m", "ordin", "doctor"],
        cwd=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    executable = environment / (
        "Scripts/ordin-assure.exe" if sys.platform == "win32" else "bin/ordin-assure"
    )
    cli = subprocess.run(
        [str(executable), "challenge", "list", "--json"],
        cwd=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "TEMP": str(environment),
            "TMP": str(environment),
            "TMPDIR": str(environment),
        },
    )
    cli_output = json.loads(cli.stdout)
    if (
        cli_output.get("execution") != "bounded_synthetic_only"
        or len(cli_output.get("properties", ())) != 10
    ):
        raise ValueError("installed console entrypoint differs from its offline property catalog")
    return {
        "schema_version": "ordin.assurance_wheel_check.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_entries": len(names),
        "source_files_compared": source_files,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "smoke": smoke,
        "doctor": doctor.stdout,
        "console_entrypoint": {
            "name": "ordin-assure",
            "command": "challenge list --json",
            "result": cli_output,
        },
        "limitations": ["Single local platform/Python run; no remote CI result implied."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.wheel, args.venv)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        json.dumps(
            {
                "ok": report["smoke"]["ok"],
                "schemas": report["smoke"]["schemas"],
                "source_files_compared": len(report["source_files_compared"]),
                "standalone_examples": report["smoke"]["standalone_examples"]["example_count"],
                "assurance_modules_imported": len(report["smoke"]["assurance_modules_imported"]),
                "optional_solver": report["smoke"]["optional_solver_unavailable"]["solver_result"],
                "console_entrypoint": "passed",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
