"""Build both wheels and test them outside the source checkout in a fresh venv."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--framework", choices=("base", "langgraph", "autogen", "crewai-quarantine"), required=True
    )
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--wheel-dir", type=Path)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    wheels = args.wheel_dir.resolve() if args.wheel_dir else workspace / "wheels"
    wheels.mkdir(exist_ok=True)
    if args.wheel_dir is None:
        _build(wheels)
    core = next(wheels.glob("ordin-*.whl"))
    swarm = next(wheels.glob("ordin_swarm-*.whl"))
    with zipfile.ZipFile(swarm) as archive:
        package = ROOT / "integrations/swarm"
        for source in (package / "ordin_swarm").rglob("*.py"):
            if archive.read(source.relative_to(package).as_posix()) != source.read_bytes():
                raise ValueError("adapter wheel differs from current source")
    with zipfile.ZipFile(core) as archive:
        for relative in ("ordin/schema.py", "ordin/swarm/gateway.py"):
            if archive.read(relative) != (ROOT / relative).read_bytes():
                raise ValueError(
                    "trusted core adapter dependency wheel differs from current source"
                )
        for source in (ROOT / "ordin/resources/schemas").glob("swarm-framework-*.json"):
            if archive.read(source.relative_to(ROOT).as_posix()) != source.read_bytes():
                raise ValueError("framework schema wheel differs from current source")
    environment = workspace / "env"
    if environment.exists():
        raise ValueError("wheel smoke requires a new isolated environment")
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    _verify(args, workspace, environment, core, swarm)


def _build(wheels):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheels),
            str(ROOT),
            str(ROOT / "integrations/swarm"),
        ],
        check=True,
    )


def _verify(args, workspace, environment, core, swarm):
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    settings = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "CREWAI_TELEMETRY_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true",
        "LANGSMITH_TRACING": "false",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    temporary = workspace / "tmp"
    temporary.mkdir()
    settings["TMPDIR"] = str(temporary)

    def run(*arguments):
        subprocess.run([str(python), *arguments], check=True, env=settings, cwd=workspace)

    active_sdk = args.framework in {"langgraph", "autogen"}
    if active_sdk:
        run(
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            str(ROOT / "requirements" / ("swarm-" + args.framework + ".txt")),
        )
    run(
        "-m",
        "pip",
        "install",
        "--no-deps",
        str(core),
        str(swarm) + ("[" + args.framework + "]" if active_sdk else ""),
    )
    run("-m", "pip", "check")
    run(
        "-I",
        "-c",
        "from importlib.resources import files; from ordin_swarm.adapters import LangGraphAdapter,CrewAIAdapter,AutoGenAdapter,CustomRuntimeAdapter; assert files('ordin_swarm').joinpath('migrations/0001-coordinator.sql').is_file()",
    )
    if args.framework == "crewai-quarantine":
        run("-I", str(ROOT / "scripts/check_swarm_crewai_quarantine.py"))
    elif args.framework == "base":
        run(
            "-I",
            "-c",
            "from importlib.util import find_spec; assert all(find_spec(v) is None for v in ('langgraph','crewai','autogen_core','openai')); from ordin_swarm.demo import run; r=run('custom'); assert r['allowed_read_completed'] and r['source_flow_violated'] and r['denied_reviews']==2 and not r['physical_enforcement']",
        )
    else:
        settings["ORDIN_REQUIRED_FRAMEWORK"] = args.framework
        run(
            "-m",
            "pytest",
            "-q",
            str(ROOT / "integrations/swarm/tests"),
            "-k",
            args.framework,
            "--basetemp",
            str(workspace / "pytest"),
            "--tb=short",
            "--disable-warnings",
        )
    print("installed-wheel smoke passed: " + args.framework)


if __name__ == "__main__":
    main()
