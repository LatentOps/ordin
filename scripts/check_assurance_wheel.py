"""Verify an explicitly supplied local wheel in a fresh workspace-only venv.

Uses local pip with --no-index/--no-deps, launches no reviewed action and
performs no scanner/model/provider setup. Refuses to reuse an existing venv.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import venv
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SMOKE = r"""
import json, socket
def refuse_network(*args, **kwargs):
    raise AssertionError("default assurance attempted network access")
class NoNetworkSocket(socket.socket):
    def __new__(cls, *args, **kwargs):
        return refuse_network(*args, **kwargs)
socket.create_connection = refuse_network
socket.socket = NoNetworkSocket
import ordin
import ordin.assurance as assurance
from ordin.schema import SCHEMA_FILES, validate_schema_files, resource_parity_errors
from ordin.assurance._schemas import SCHEMAS
from ordin.assurance import SecurityProfile, RepositoryScope, ModelAnswer
from ordin import ActionEnvelope, AgentGate
assert all(name in SCHEMA_FILES for name in SCHEMAS)
assert validate_schema_files() == []
assert resource_parity_errors() == []
profile = SecurityProfile("fixture", "1", RepositoryScope("fixture/repo", "snapshot-1"))
assert SecurityProfile.from_json(json.dumps(profile.as_dict())) == profile
assert AgentGate().evaluate_action(ActionEnvelope.shell("git status --short")).disposition == "execute"
assert AgentGate().evaluate_action(ActionEnvelope.shell("rm -rf /")).disposition == "deny"
assert ModelAnswer("risk", 0.5).p_yes == 0.5
print(json.dumps({"ok": True, "version": ordin.__version__, "schemas": len(SCHEMA_FILES),
                  "assurance_schemas": len(SCHEMAS), "exports": sorted(assurance.__all__),
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
        }
        if not required <= names:
            raise ValueError("wheel is missing assurance modules")
        metadata = archive.read(next(name for name in names if name.endswith("/METADATA"))).decode()
        if any(
            line.startswith("Requires-Dist:") and "extra ==" not in line
            for line in metadata.splitlines()
        ):
            raise ValueError("wheel added a mandatory dependency")
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
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
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
    return {
        "schema_version": "ordin.assurance_wheel_check.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "wheel_entries": len(names),
        "smoke": smoke,
        "doctor": doctor.stdout,
        "limitations": ["Local Windows/Python version only; no remote CI result implied."],
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
    print(json.dumps(report["smoke"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
