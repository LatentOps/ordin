"""An installed-wheel CI gate must reject editable/source imports and overlays."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/run_installed_assurance_tests.py"
spec = importlib.util.spec_from_file_location("installed_assurance_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_source_import_cannot_pass_as_an_installed_distribution(tmp_path, monkeypatch):
    source = tmp_path / "source/ordin/__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text("", encoding="utf-8")
    module = ModuleType("ordin")
    module.__file__ = str(source)
    monkeypatch.setitem(sys.modules, "ordin", module)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))
    with pytest.raises(ValueError, match="installed wheel"):
        runner.pin_installed_namespace("ordin")


def test_install_is_pinned_and_later_source_overlay_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "venv/Lib/site-packages/ordin"
    root.mkdir(parents=True)
    (root / "__init__.py").write_text("", encoding="utf-8")
    module = ModuleType("ordin")
    module.__file__ = str(root / "__init__.py")
    monkeypatch.setitem(sys.modules, "ordin", module)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))
    assert runner.pin_installed_namespace("ordin") == root
    leaf = ModuleType("ordin.source_overlay")
    leaf.__file__ = str(tmp_path / "source/ordin/source_overlay.py")
    monkeypatch.setitem(sys.modules, leaf.__name__, leaf)
    with pytest.raises(ValueError, match="source overlay"):
        runner.check_loaded_namespaces({"ordin": root})


def test_missing_origin_cannot_pass_namespace_audit(tmp_path, monkeypatch):
    module = ModuleType("ordin.missing_origin")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    with pytest.raises(ValueError, match="source overlay"):
        runner.check_loaded_namespaces({"ordin": tmp_path})
