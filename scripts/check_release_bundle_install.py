"""Install the exact verified base bundle offline into a new environment and inspect its bytes."""

import sys

if __name__ == "__main__" and not sys.flags.isolated:
    raise SystemExit(
        "Release tooling requires isolated Python: use python -I -B scripts/"
        + __file__.replace("\\", "/").rsplit("/", 1)[-1]
    )


import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def _bundle_helper(filename="release_bundle.py"):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location("_ordin_release_bundle", path)
    if spec is None:
        raise ValueError("exact release bundle helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


verify_bundle = _bundle_helper().verify_bundle
_TOOLS = _bundle_helper("_release_tools.py")


PROBE = """import hashlib,importlib,json,pathlib,sys
from importlib.metadata import distribution
manifest=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(manifest['packages'])=={'ordin','ordin-swarm','ordin-runtime','ordin-security','ordin-decision-models'}
checkout=pathlib.Path(sys.argv[2]).resolve()
observed={}
for name,package in manifest['packages'].items():
    installed=distribution(name)
    assert installed.version==package['version'], name
    root=pathlib.Path(installed.locate_file('')).resolve()
    assert root.is_relative_to(pathlib.Path(sys.prefix).resolve()), name
    direct=installed.read_text('direct_url.json')
    assert not direct or not json.loads(direct).get('dir_info',{}).get('editable'), name
    expected=package['payload_sha256']
    module=name.replace('-','_')
    assert all(path.startswith(module+'/') for path in expected), name
    origin=root/module
    assert not origin.is_relative_to(checkout), name
    actual={}
    for path in origin.rglob('*'):
        if path.is_file() and path.suffix!='.pyc' and '__pycache__' not in path.parts:
            assert not path.is_symlink(), name
            actual[path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual==expected, name
    observed[name]={'version':installed.version,'payload_files':len(actual),'origin':str(origin)}
for name in observed:
    importlib.import_module(name.replace('-','_'))
print(json.dumps(observed,sort_keys=True))
"""


def check_install(
    bundle: Path, workspace: Path, *, source_root: Path, revision: str, tag: str | None = None
) -> dict:
    identity = verify_bundle(bundle, source_root=source_root, revision=revision, tag=tag)
    workspace = workspace.absolute()
    if workspace.exists() or workspace.is_symlink():
        raise ValueError("bundle install verification requires a new workspace")
    if workspace.resolve().is_relative_to(source_root.resolve()):
        raise ValueError("bundle install workspace must be outside the source checkout")
    workspace.mkdir(mode=0o700, parents=True)
    settings = _TOOLS.child_environment(workspace)
    captured = workspace / "verified-bundle.json"
    with captured.open("x", encoding="utf-8") as stream:
        json.dump(identity, stream, sort_keys=True)
    subprocess.run(
        [sys.executable, "-I", "-B", "-m", "venv", str(workspace / "env")],
        cwd=workspace,
        env=settings,
        check=True,
        timeout=120,
    )
    python = workspace / "env" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--find-links",
            str(bundle),
            *[str(bundle / package["wheel"]) for package in identity["packages"].values()],
        ],
        cwd=workspace,
        check=True,
        timeout=120,
        env=settings,
    )
    subprocess.run(
        [str(python), "-I", "-m", "pip", "check"],
        cwd=workspace,
        env=settings,
        check=True,
        timeout=30,
    )
    observed = json.loads(
        subprocess.check_output(
            [str(python), "-I", "-B", "-c", PROBE, str(captured), str(source_root)],
            cwd=workspace,
            text=True,
            timeout=60,
            env=settings,
        )
    )
    scripts = python.parent
    for command in ("ordin", "ordin-swarm-adapter", "ordin-swarm-host", "ordin-runtime"):
        subprocess.run(
            [str(scripts / (command + (".exe" if os.name == "nt" else ""))), "--help"],
            cwd=workspace,
            check=True,
            stdout=subprocess.DEVNULL,
            timeout=30,
            env=settings,
        )
    # Revalidate original bytes after the installer and command probes complete.
    if verify_bundle(bundle, source_root=source_root, revision=revision, tag=tag) != identity:
        raise ValueError("verified bundle changed during installation")
    result = {
        "schema_version": "ordin.bundle_install.v1",
        "revision": revision,
        "tree": identity["tree"],
        "packages": observed,
        "offline_install": True,
        "source_imports": False,
        "execution_authority": False,
        "publication_authorized": False,
    }
    (workspace / "bundle-install.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tag")
    args = parser.parse_args()
    check_install(
        args.bundle.resolve(strict=True),
        args.workspace,
        source_root=Path(__file__).resolve().parents[1],
        revision=args.revision,
        tag=args.tag,
    )
    print("Verified the offline five-package installation and its exact installed payloads.")


if __name__ == "__main__":
    main()
