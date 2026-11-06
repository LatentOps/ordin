"""Verify the corpus from an isolated installed wheel at an exact clean revision."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--long-actions", type=int, default=1024)
    args = parser.parse_args()
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision) or args.revision != revision:
        raise ValueError("installed corpus requires the exact checkout revision")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    wheels = workspace / "wheels"
    wheels.mkdir()
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
        ],
        check=True,
    )
    wheel = next(wheels.glob("ordin-*.whl"))
    owned = list((ROOT / "ordin").rglob("*.py")) + list((ROOT / "ordin/resources").rglob("*"))
    with zipfile.ZipFile(wheel) as archive:
        for path in owned:
            if (
                path.is_file()
                and archive.read(path.relative_to(ROOT).as_posix()) != path.read_bytes()
            ):
                raise ValueError("installed corpus artifact differs from the exact source")
    environment = workspace / "env"
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    temporary = workspace / "tmp"
    temporary.mkdir()
    settings = {**os.environ, "TMPDIR": str(temporary), "PIP_DISABLE_PIP_VERSION_CHECK": "1"}

    def run(*arguments):
        subprocess.run([str(python), "-I", *arguments], cwd=workspace, env=settings, check=True)

    run("-m", "pip", "install", "--no-deps", str(wheel))
    run(
        "-c",
        "from importlib.util import find_spec; assert all(find_spec(v) is None for v in ('openai','langgraph','crewai','autogen_core')); from ordin.swarm.benchmark import evaluate; from ordin.schema import validate_named_schema; a=evaluate(revision='"
        + revision
        + "'); b=evaluate(revision='"
        + revision
        + "'); assert a['ok'] and a['result_sha256']==b['result_sha256']; assert a['metrics']['kernel_not_run']>0 and a['metrics']['authenticated_kernel_completions']==0; assert not validate_named_schema('swarm_corpus_report',a)",
    )
    run(
        "-m",
        "ordin.swarm.benchmark_cli",
        "corpus",
        "--kernel",
        "--revision",
        revision,
        "--output",
        str(workspace / "kernel.json"),
        "--markdown",
        str(workspace / "kernel.md"),
    )
    run(
        "-m",
        "ordin.swarm.benchmark_cli",
        "overhead",
        "--revision",
        revision,
        "--samples",
        str(args.samples),
        "--long-actions",
        str(args.long_actions),
        "--output",
        str(workspace / "overhead.json"),
        "--markdown",
        str(workspace / "overhead.md"),
    )
    print("Installed offline corpus, original kernel evidence, and unchanged latency gates passed.")


if __name__ == "__main__":
    main()
