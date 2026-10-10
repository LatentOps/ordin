"""Capture private wheel verification as bounded, source-pinned public evidence."""

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--check", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    changed = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "diff",
            "--quiet",
            args.revision,
            "--",
            "ordin",
            "schemas",
            "pyproject.toml",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if changed.returncode:
        raise ValueError("package differs from pinned source")
    with zipfile.ZipFile(args.wheel) as archive:
        count = 0
        for name in archive.namelist():
            if name.startswith("ordin/") and name.endswith((".py", ".json")):
                assert archive.read(name) == (ROOT / name).read_bytes()
                count += 1
    raw = args.check.read_bytes()
    if len(raw) > 1_048_576:
        raise ValueError("private wheel check byte limit")
    check = json.loads(raw)
    check["doctor_stdout_sha256"] = hashlib.sha256(check.pop("doctor").encode()).hexdigest()
    check["doctor_verified_success"] = True
    wheel_digest = hashlib.sha256(args.wheel.read_bytes()).hexdigest()
    if check["wheel_sha256"] != wheel_digest:
        raise ValueError("verification belongs to another wheel")
    report = {
        "schema_version": "ordin.assurance_pinned_wheel_evidence.v1",
        "implemented_revision": args.revision,
        "wheel_sha256": wheel_digest,
        "wheel_source_files_compared": count,
        "wheel_check": check,
        "limitations": [
            "Local Windows/Python 3.13 offline verification; no actual host execution boundary or remote CI exercised."
        ],
    }
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "revision": args.revision,
                "wheel_source_files_compared": count,
                "schemas": check["smoke"]["schemas"],
                "assurance_schemas": check["smoke"]["assurance_schemas"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
