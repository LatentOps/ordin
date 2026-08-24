import tomllib
from pathlib import Path

import commandgraph


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_version_matches_project_metadata():
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert commandgraph.__version__ == pyproject["project"]["version"]
