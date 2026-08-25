from __future__ import annotations

import importlib.util
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHECK_PATH = PROJECT_ROOT / "scripts" / "check_namespace.py"


def _load_namespace_checker():
    spec = importlib.util.spec_from_file_location("ordin_namespace_check", CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_namespace_guard_accepts_clean_tree(tmp_path):
    checker = _load_namespace_checker()
    (tmp_path / "README.md").write_text("Ordin is clean.\n", encoding="utf-8")

    assert checker.legacy_namespace_failures(tmp_path) == []


def test_namespace_guard_detects_legacy_identity(tmp_path):
    checker = _load_namespace_checker()
    legacy_name = "command" + "graph"
    (tmp_path / "README.md").write_text(f"old package: {legacy_name}\n", encoding="utf-8")

    failures = checker.legacy_namespace_failures(tmp_path)

    assert len(failures) == 1
    assert failures[0].startswith("README.md: contains legacy token")
