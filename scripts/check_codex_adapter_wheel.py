"""Install the local core/adapter wheels offline and verify their namespace."""

import argparse
import hashlib
import json
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = r"""
import json, socket, subprocess
def forbidden(*args, **kwargs):
    raise AssertionError("adapter attempted network or subprocess execution")
class NoNetworkSocket(socket.socket):
    def __new__(cls,*args,**kwargs): return forbidden(*args,**kwargs)
socket.socket=NoNetworkSocket
socket.create_connection=forbidden
subprocess.Popen=forbidden
from ordin_codex_security import ImportScope, import_codex_json, import_sarif
from ordin.assurance.codex_security._validation import schema
assert schema("findings")["properties"]["schemaVersion"]["const"]=="1.0"
print(json.dumps({"ok":True,"namespace":"ordin_codex_security","models_or_scanner_loaded":False}))
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
        raise ValueError("adapter verification requires new workspace-only environment")
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
            str(args.core_wheel.absolute()),
            str(args.adapter_wheel.absolute()),
        ],
        cwd=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if installed.returncode:
        raise ValueError("offline adapter installation failed")
    checked = subprocess.run(
        [str(interpreter), "-I", "-c", SMOKE],
        cwd=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if checked.returncode:
        raise ValueError("isolated adapter namespace smoke failed")
    report = {
        "schema_version": "ordin.codex_security_adapter_wheel_check.v1",
        "smoke": json.loads(checked.stdout),
        "core_wheel_sha256": hashlib.sha256(args.core_wheel.read_bytes()).hexdigest(),
        "adapter_wheel_sha256": hashlib.sha256(args.adapter_wheel.read_bytes()).hexdigest(),
        "limitations": ["Local Windows/Python 3.13 only; no scanner/provider or remote CI run."],
    }
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(report["smoke"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
