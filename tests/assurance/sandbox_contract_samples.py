"""No-execution examples for optional sandbox data contracts; not grant receipts."""

import json
import sys
import threading
from pathlib import Path

from ordin.assurance import (
    AuthorizedRepository,
    HostEvidenceSource,
    RepositoryScope,
    SyntheticPathCase,
    SyntheticPathSuite,
    VettedSandboxRuntime,
    LinuxVettedSandboxRuntime,
    load_vetted_program,
    load_synthetic_suite,
    run_sandbox_test,
)
from .test_validation import reference


def sandbox_contract_samples(tmp_path):
    root = tmp_path / "sandbox-data-contracts"
    root.mkdir()
    scope = AuthorizedRepository(
        root.resolve(), RepositoryScope("fixture/synthetic", "snapshot-1"), "/fixture"
    )
    (root / "guard.py").write_bytes(
        b"def within_root(path, root):\n    return path.startswith(root)\n"
    )
    suite_data = SyntheticPathSuite(
        "contract-suite",
        (
            SyntheticPathCase("benign", "/synthetic/project/file", "/synthetic/project"),
            SyntheticPathCase("collision", "/synthetic/project-other", "/synthetic/project"),
        ),
    )
    (root / "suite.json").write_bytes(json.dumps(suite_data.as_dict()).encode())
    program = load_vetted_program(scope, reference(scope, "guard.py"))
    suite = load_synthetic_suite(scope, reference(scope, "suite.json"))
    source = HostEvidenceSource("fixture-agent", scope.repository, "a" * 64, 1, "b" * 64, "c" * 64)
    worker = Path(__file__).resolve().parents[2] / "ordin/assurance/_sandbox_worker.py"
    # Deliberately unapproved configuration inside the checkout cannot execute.
    runtime = VettedSandboxRuntime(
        Path(sys.executable).absolute(),
        "a" * 64,
        worker,
        "b" * 64,
        (str(worker),),
        root.resolve(),
        root.resolve(),
        "c" * 64,
        (root.resolve(),),
    )
    cancel = threading.Event()
    cancel.set()
    record = run_sandbox_test(scope, source, runtime, program, suite, None, cancel=cancel)
    linux = LinuxVettedSandboxRuntime(
        **{name: getattr(runtime, name) for name in runtime.__dataclass_fields__}
    )
    linux_record = run_sandbox_test(scope, source, linux, program, suite, None, cancel=cancel)
    return {
        "assurance_linux_sandbox_test": linux_record.as_dict(),
        "assurance_synthetic_path_suite": suite_data.as_dict(),
        "assurance_vetted_program": program.as_dict(),
        "assurance_sandbox_test": record.as_dict(),
        "assurance_source_fix": {
            "schema_version": "ordin.assurance_source_fix.v1",
            "proposal_digest": "a" * 64,
            "original_validation_digest": "b" * 64,
            "original_run_digest": None,
            "candidate_run_digest": None,
            "repository_before": scope.repository.as_dict(),
            "repository_after": RepositoryScope(scope.repository.id, "snapshot-2").as_dict(),
            "original_source_digest": "c" * 64,
            "candidate_source_digest": "d" * 64,
            "suite_digest": suite.source.content_digest,
            "result": "inconclusive",
            "authority_delta": "unknown",
            "benign_regressions": 0,
            "false_allows": 0,
            "proof_gaps": ["No actual sandbox source fix is attested by this data example."],
            "tested_scope": "synthetic_path_boundary",
            "integrated": False,
            "limitations": [
                "Schema example only; JSON cannot recreate an actual source-fix receipt."
            ],
        },
    }
