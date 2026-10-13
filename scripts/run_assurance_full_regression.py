"""Run original and Assurance tests against a selected installed local wheel.

Keeps detailed output private, records full JUnit evidence, and preserves every
test/skip/threshold. No scanner, model, publication or policy installation.
"""

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--suite", choices=("all", "core"), default="all")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("regression requires an exact source commit")
    if (
        subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
        != args.revision
    ):
        raise ValueError("regression revision differs from current checkout")
    if subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            args.revision,
            "--",
            "ordin",
            "tests",
            "integrations",
            "pyproject.toml",
            "scripts/run_assurance_full_regression.py",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    ).returncode:
        raise ValueError("regression sources differ from pinned revision")
    interpreter = args.python.resolve(strict=True)
    output = args.output.resolve()
    if not interpreter.is_relative_to(ROOT / ".assurance-work") or not output.is_relative_to(
        ROOT / ".assurance-work"
    ):
        raise ValueError(
            "regression environment/evidence must stay within the workspace scratch directory"
        )
    output.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment["PATH"] = str(interpreter.parent) + os.pathsep + environment.get("PATH", "")
    script = "import sys,ordin,pytest; from pathlib import Path; assert Path(ordin.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()); raise SystemExit(pytest.main(sys.argv[1:]))"
    test_paths = ["tests"]
    if args.suite == "all":
        test_paths.extend(("integrations/openshell/tests", "integrations/decision_models/tests"))
    command = [
        str(interpreter),
        "-I",
        "-c",
        script,
        "-q",
        "-ra",
        "-p",
        "no:cacheprovider",
        "--basetemp=" + str(output / "tmp"),
        "--junitxml=" + str(output / "junit.xml"),
        *test_paths,
    ]
    metadata = {
        "schema_version": "ordin.assurance_full_regression.v2",
        "revision": args.revision,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "test_paths": test_paths,
        "suite": args.suite,
        "limitations": ["Windows/Python 3.13 local installed-wheel run; no remote CI claim."],
    }
    (output / "state.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    try:
        with (output / "output.txt").open("w", encoding="utf-8") as log:
            result = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=3600,
            )
        returncode = result.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        metadata["error_class"] = type(error).__name__
        returncode = 124 if isinstance(error, subprocess.TimeoutExpired) else 1
    metadata.update(
        status="completed",
        returncode=returncode,
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
    (output / "state.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
