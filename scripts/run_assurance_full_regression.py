"""Run original and Assurance tests against a selected installed local wheel.

Keeps detailed output private, records full JUnit evidence, and preserves every
test/skip/threshold. No scanner, model, publication or policy installation.
"""

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
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
    script = "import sys,ordin,pytest; assert '.assurance-work' in ordin.__file__; raise SystemExit(pytest.main(sys.argv[1:]))"
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
        "tests",
    ]
    metadata = {
        "schema_version": "ordin.assurance_full_regression.v1",
        "revision": args.revision,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "limitations": ["Windows/Python 3.13 local installed-wheel run; no remote CI claim."],
    }
    (output / "state.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
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
    metadata.update(
        status="completed",
        returncode=result.returncode,
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
    (output / "state.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
