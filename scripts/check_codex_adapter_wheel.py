"""Fresh offline combined wheel install and source-independent adapter imports."""

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
import json, socket, subprocess, sys
from pathlib import Path
def refuse(*args, **kwargs):
    raise AssertionError("adapter attempted network/process creation")
class NoSocket(socket.socket):
    def __new__(cls, *args, **kwargs):
        return refuse(*args, **kwargs)
socket.socket = NoSocket
socket.create_connection = refuse
subprocess.Popen = refuse
import ordin_codex_security as adapter
assert all(hasattr(adapter, name) for name in ("ImportScope", "import_codex_json", "import_sarif"))
from ordin_codex_security.provider import mock_scanner_run, ScannerSelection
from ordin.assurance.codex_security._validation import schema
assert mock_scanner_run(exit_code=1).status == "severity_violation"
assert mock_scanner_run(exit_code=2).status == "incomplete"
assert schema("findings")["type"] == "object"
assert schema("findings")["properties"]["schemaVersion"]["const"] == "1.0"
assert Path(adapter.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
print(json.dumps({"ok": True, "namespace": "ordin_codex_security", "models_or_scanner_loaded": False,
                  "namespace_imported": True, "provider_imported": True,
                  "pinned_schema_loaded": True, "real_scanner_invoked": False,
                  "network_process_calls_rejected": True}))
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
        raise ValueError("adapter check requires a new workspace venv")
    with zipfile.ZipFile(args.adapter_wheel) as archive:
        matched = 0
        for name in archive.namelist():
            if name.startswith("ordin_codex_security/"):
                if archive.read(name) != (ROOT / "integrations/codex_security" / name).read_bytes():
                    raise ValueError("adapter wheel differs from source")
                matched += 1
        if "ordin_codex_security/provider.py" not in archive.namelist():
            raise ValueError("adapter lacks explicit provider module")
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
        check=False,
        timeout=120,
    )
    if installed.returncode:
        raise ValueError("offline adapter installation failed")
    result = subprocess.run(
        [str(interpreter), "-I", "-c", SMOKE],
        cwd=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise ValueError("isolated adapter namespace/provider smoke failed")
    report = {
        "schema_version": "ordin.codex_security_adapter_wheel_check.v1",
        "core_wheel_sha256": hashlib.sha256(args.core_wheel.read_bytes()).hexdigest(),
        "adapter_wheel_sha256": hashlib.sha256(args.adapter_wheel.read_bytes()).hexdigest(),
        "adapter_source_files_compared": matched,
        "smoke": json.loads(result.stdout),
        "limitations": [
            "Local Windows/Python 3.13 only; no live scanner or remote runner checked."
        ],
    }
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(report["smoke"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
