"""Verify separate optional model wheel offline, outside checkout import paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = r"""
import json, socket, subprocess, sys, contextlib, io
from pathlib import Path
def refuse(*args, **kwargs):
    raise AssertionError("optional import/default path attempted network/process")
class NoSocket(socket.socket):
    def __new__(cls, *args, **kwargs): return refuse(*args, **kwargs)
socket.socket = NoSocket
socket.create_connection = refuse
class NoProcess(subprocess.Popen):
    def __init__(self, *args, **kwargs): refuse(*args, **kwargs)
subprocess.Popen = NoProcess
from ordin import Ordin, AgentGate, ActionEnvelope
import ordin_decision_models as models
from ordin_decision_models.typesafe import TypeSafeConfiguration
assert Path(models.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
provider = models.MockDecisionModel()
router = models.SemanticInspectionRouter(provider=provider)
result = router.evaluate_action(ActionEnvelope.shell("git status --short"))
assert result.may_execute and provider.calls == 0
assert router.evaluate_action(ActionEnvelope.shell("rm -rf /")).denied and provider.calls == 0
from ordin_decision_models.demo import main
with contextlib.redirect_stdout(io.StringIO()) as stream:
    assert main() == 0
example = json.loads(stream.getvalue())
assert example["actions_executed"] is False and example["model_effectiveness_evaluated"] is False
assert [r["provider_calls"] for r in example["results"]] == [0,1,1]
assert [r["result"]["disposition"] for r in example["results"]] == ["execute","execute","escalate"]
assert not any(name in sys.modules for name in ("laya", "torch", "transformers", "huggingface_hub"))
print(json.dumps({"namespace_imported":True,"default_provider_calls":0,"offline_demo_passed":True,
                  "no_actions_executed":True,"heavy_model_packages_loaded":False,
                  "network_process_calls_rejected":True}))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-wheel", type=Path, required=True)
    parser.add_argument("--adapter-wheel", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    environment = args.venv.absolute()
    if (
        not environment.resolve().is_relative_to(ROOT)
        or environment == ROOT
        or environment.exists()
    ):
        raise ValueError("model adapter check requires a new workspace venv")
    with zipfile.ZipFile(args.adapter_wheel) as archive:
        count = 0
        for name in archive.namelist():
            if name.startswith("ordin_decision_models/"):
                if (
                    archive.read(name)
                    != (ROOT / "integrations/decision_models" / name).read_bytes()
                ):
                    raise ValueError("optional model wheel differs from source")
                count += 1
        metadata = archive.read(
            next(n for n in archive.namelist() if n.endswith("/METADATA"))
        ).decode()
        if any(
            line.startswith("Requires-Dist:")
            and "extra ==" not in line
            and not line.startswith("Requires-Dist: ordin")
            for line in metadata.splitlines()
        ):
            raise ValueError("optional base package requires heavy model dependencies")
    venv.EnvBuilder(with_pip=False).create(environment)
    interpreter = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    installed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "--python",
            str(interpreter),
            "install",
            "--no-index",
            "--no-deps",
            str(args.core_wheel.resolve()),
            str(args.adapter_wheel.resolve()),
        ],
        cwd=environment,
        capture_output=True,
        timeout=120,
    )
    if installed.returncode:
        raise ValueError("offline model adapter installation failed")
    checked = subprocess.run(
        [str(interpreter), "-I", "-c", SMOKE],
        cwd=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if checked.returncode:
        raise ValueError("isolated model adapter smoke failed")
    packet = {
        "schema_version": "ordin.decision_models_wheel_check.v1",
        "core_wheel_sha256": hashlib.sha256(args.core_wheel.read_bytes()).hexdigest(),
        "adapter_wheel_sha256": hashlib.sha256(args.adapter_wheel.read_bytes()).hexdigest(),
        "source_files_compared": count,
        "smoke": json.loads(checked.stdout),
        "limitations": [
            "Local offline mock/import verification only; no actual hosted/local model effectiveness, weights or remote CI result."
        ],
    }
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(packet, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(packet["smoke"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
