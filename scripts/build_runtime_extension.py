"""Build or check the audited local OpenShell request authority extension."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "integrations/openshell"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", required=True, type=Path, help="Upstream checkout or verified patched source"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument(
        "--vm-assets", type=Path, help="Verified compressed libkrun/kernel/umoci runtime assets"
    )
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if source == output or source in output.parents:
        raise ValueError("runtime output must be separate from the source")
    identity = json.loads((INTEGRATION / "ordin_openshell/runtime_identity.json").read_text())
    patch = INTEGRATION / "runtime/patches/request-authority-v1.patch"
    if hashlib.sha256(patch.read_bytes()).hexdigest() != identity["patch_sha256"]:
        raise ValueError("runtime patch digest mismatch")
    for name, expected in identity["files"].items():
        path = source / name
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != expected
        ):
            raise ValueError("runtime source differs from the audited patch manifest")
    output.mkdir(parents=True, exist_ok=True)
    env = dict(
        os.environ,
        ORDIN_RUNTIME_SOURCE_DIGEST=identity["source_digest"],
        OPENSHELL_GIT_VERSION="0.1.2",
    )
    cargo_program = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    if not Path(cargo_program).is_file():
        raise ValueError("pinned Rust toolchain is unavailable")
    env["PATH"] = str(Path(cargo_program).parent) + os.pathsep + env.get("PATH", "")
    env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "2")
    env.pop("RUSTC_WRAPPER", None)

    def cargo(*arguments):
        subprocess.run([cargo_program, "+1.95.0", *arguments], cwd=source, env=env, check=True)

    if args.check_only:
        cargo("fmt", "--all", "--", "--check")
        cargo(
            "clippy",
            "-p",
            "openshell-request-integrity",
            "-p",
            "openshell-policy-schema",
            "-p",
            "openshell-policy",
            "-p",
            "openshell-supervisor-network",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        )
        cargo(
            "test",
            "-p",
            "openshell-request-integrity",
            "-p",
            "openshell-policy-schema",
            "-p",
            "openshell-policy",
            "-p",
            "openshell-supervisor-network",
            "--lib",
            "--",
            "--test-threads=1",
        )
        return 0
    cargo("build", "--release", "-p", "openshell-cli", "-p", "openshell-supervisor")
    cargo(
        "build",
        "--release",
        "-p",
        "openshell-gateway",
        "--no-default-features",
        "--features",
        "compute-driver-vm,bundled-z3",
    )
    if args.vm_assets is None:
        raise ValueError("full runtime build requires verified VM assets")
    assets = output / "vm-runtime-compressed"
    assets.mkdir(exist_ok=True)
    for name in ("libkrun.so.zst", "libkrunfw.so.5.zst", "umoci.zst"):
        shutil.copyfile(args.vm_assets.resolve() / name, assets / name)
    env["OPENSHELL_VM_RUNTIME_COMPRESSED_DIR"] = str(assets)
    subprocess.run(
        ["bash", "tasks/scripts/vm/build-supervisor-bundle.sh", "--arch", "x86_64"],
        cwd=source,
        env=env,
        check=True,
    )
    cargo(
        "build",
        "--release",
        "-p",
        "openshell-driver-vm",
        "--no-default-features",
        "--features",
        "compute-driver",
    )
    binaries = {}
    for name in ("openshell", "openshell-supervisor", "openshell-gateway", "openshell-driver-vm"):
        path = output / name
        shutil.copyfile(source / "target/release" / name, path)
        path.chmod(0o755)
        binaries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = {
        **identity,
        "binaries": binaries,
        "vm_assets": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in assets.iterdir()
            if p.is_file()
        },
    }
    (output / "runtime-build.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps({"source_digest": identity["source_digest"], "built_programs": sorted(binaries)})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
