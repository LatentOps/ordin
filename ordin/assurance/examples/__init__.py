"""Runnable, owned offline fixtures; no reviewed action or target code executes."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib
from importlib.resources import files
import io
import json
from pathlib import Path
import tempfile


EXAMPLES = (
    "attack_path",
    "codex_import",
    "delegation",
    "gate_review",
    "policy_simulation",
    "profile_inventory",
    "property_challengers",
    "source_diff",
)


def run_examples(*, scratch_root: Path | None = None) -> dict:
    """Exercise every shipped standalone fixture with temporary private artifacts.

    Only this closed list of project-owned modules is imported. Caller data
    cannot choose a program, interpreter, command or source to execute. The
    report contains code/output digests and fixture results, never artifact paths.
    Network/process spies belong to the verification harness; this runner makes
    no claim to enforce an OS sandbox.
    """
    package = files(__package__)
    shipped = {p.name for p in package.iterdir() if p.name.endswith(".py")}
    expected = {name + ".py" for name in EXAMPLES} | {"__init__.py", "__main__.py"}
    if shipped != expected:
        raise ValueError("standalone example inventory differs from its audited manifest")
    results = []
    with tempfile.TemporaryDirectory(
        prefix="ordin-offline-examples-", dir=scratch_root
    ) as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir(mode=0o700)
        (source / "README.md").write_text("# Owned synthetic application\n", encoding="utf-8")
        (source / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
        for name in EXAMPLES:
            module = importlib.import_module(__package__ + "." + name)
            arguments = None
            if name in {"codex_import", "delegation", "gate_review", "source_diff"}:
                arguments = ["--output", str(root / name)]
            elif name == "profile_inventory":
                arguments = [
                    "--repository-root",
                    str(source),
                    "--repository-id",
                    "fixture/installed-example",
                    "--revision",
                    "fixture-v1",
                    "--virtual-root",
                    "/fixture/source",
                    "--output",
                    str(root / name),
                ]
            with redirect_stdout(io.StringIO()) as stream:
                status = module.main(arguments) if arguments is not None else module.main()
            if status not in {None, 0}:
                raise ValueError("standalone example did not complete")
            raw = stream.getvalue()
            output = json.loads(raw)
            _check_result(name, output)
            results.append(
                {
                    "module": __package__ + "." + name,
                    "source_sha256": hashlib.sha256(
                        package.joinpath(name + ".py").read_bytes()
                    ).hexdigest(),
                    "stdout_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                    "result": "passed",
                }
            )
    return {
        "schema_version": "ordin.assurance_offline_examples.v1",
        "examples": results,
        "example_count": len(results),
        "all_passed": True,
        "actions_executed": False,
        "target_code_executed": False,
        "model_or_scanner_called": False,
        "artifacts_retained": False,
        "scope": "Owned synthetic offline fixtures; no physical enforcement or effectiveness claim.",
    }


def _check_result(name: str, output: dict) -> None:
    checks = {
        "attack_path": lambda: (
            output["exposure"] == "hypothesis"
            and output["reachability"] == "blocked"
            and bool(output["proof_gaps"])
        ),
        "codex_import": lambda: (
            output["completeness"] == "partial"
            and output["finding_count"] == 0
            and output["finding_confirmation"] == "not_performed"
        ),
        "delegation": lambda: (
            output["allowed_review"] == "execute"
            and output["env_review"] == "deny"
            and output["pending_use_after_parent_revocation"] is False
            and output["executes_actions"] is False
        ),
        "gate_review": lambda: (
            output["before_approval"] == "escalate"
            and output["after_approval"] == "execute"
            and output["protected_mutation"] == "deny"
            and output["binding_matches"] is True
            and output["executes_actions"] is False
        ),
        "policy_simulation": lambda: (
            output["newly_executable"] == ["unknown-tool"] and output["activation_safe"] is False
        ),
        "profile_inventory": lambda: (
            output["files"] == 2
            and output["draft_authoritative"] is False
            and output["executes_actions"] is False
        ),
        "property_challengers": lambda: (
            output["properties"] == 10
            and output["generated"] == 320
            and output["status"] == "inconclusive"
            and output["host_boundary_exercised"] is False
        ),
        "source_diff": lambda: (
            output["advisory_only"] is True
            and output["review_required"] is True
            and len(output["changes"]) == 2
        ),
    }
    if not checks[name]():
        raise ValueError("standalone example contradicted its declared fixture outcome: " + name)
