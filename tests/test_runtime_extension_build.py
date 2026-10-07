"""A build identity must describe the complete pinned source, including extras."""

import hashlib
import importlib.util
from pathlib import Path
import subprocess

import pytest


def test_runtime_build_source_rejects_unaudited_inputs(tmp_path):
    recipe = Path(__file__).resolve().parents[1] / "scripts/build_runtime_extension.py"
    spec = importlib.util.spec_from_file_location("runtime_build_recipe", recipe)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    source.mkdir()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()

    git("init", "--quiet")
    git("config", "user.name", "Build verification fixture")
    git("config", "user.email", "build-fixture@example.invalid")
    (source / "Cargo.toml").write_text("base\n")
    (source / "unchanged.rs").write_text("base\n")
    (source / ".gitignore").write_text("*.hidden.rs\n")
    git("add", ".")
    git("commit", "--quiet", "-m", "fixture base")
    identity = {
        "upstream_revision": git("rev-parse", "HEAD"),
        "files": {"Cargo.toml": hashlib.sha256(b"approved\n").hexdigest()},
    }
    (source / "Cargo.toml").write_text("approved\n")
    module.verify_source(source, identity)
    for name in ("unchanged.rs", "extra.rs", "crates/extra.hidden.rs"):
        path = source / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("unaudited\n")
        with pytest.raises(ValueError, match="unaudited changes|ignored build inputs"):
            module.verify_source(source, identity)
        if name == "unchanged.rs":
            path.write_text("base\n")
        else:
            path.unlink()
    (source / "Cargo.toml").write_text("different\n")
    with pytest.raises(ValueError, match="audited patch manifest"):
        module.verify_source(source, identity)
    (source / "Cargo.toml").write_text("approved\n")
    with pytest.raises(ValueError, match="pinned upstream revision"):
        module.verify_source(source, {**identity, "upstream_revision": "0" * 40})
    git("update-index", "--assume-unchanged", "unchanged.rs")
    (source / "unchanged.rs").write_text("hidden change\n")
    with pytest.raises(ValueError, match="pinned base"):
        module.verify_source(source, identity)
