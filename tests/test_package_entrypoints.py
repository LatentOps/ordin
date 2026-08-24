import json
import os
import subprocess
import venv
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _venv_python(venv_path: Path) -> Path:
    if os.name == "nt":
        return venv_path / "Scripts" / "python.exe"
    return venv_path / "bin" / "python"


def _venv_script(venv_path: Path, script_name: str) -> Path:
    if os.name == "nt":
        return venv_path / "Scripts" / f"{script_name}.exe"
    return venv_path / "bin" / script_name


def test_package_install_exposes_cli_entrypoints_and_graph_data(tmp_path):
    venv_path = tmp_path / "venv"
    # Python 3.12+ venvs may omit setuptools; expose the runner build backend
    # while still installing Ordin and its console scripts into this venv.
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(venv_path)
    python = _venv_python(venv_path)

    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--force-reinstall",
            str(PROJECT_ROOT),
        ],
        check=True,
        cwd=PROJECT_ROOT,
    )

    outputs = []
    for script_name in ("ordin", "ordin"):
        script = _venv_script(venv_path, script_name)
        result = subprocess.run(
            [str(script), "--help"],
            check=True,
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
        )
        assert "Intent-aware command discovery and safety checks." in result.stdout
        outputs.append(result.stdout)

        doctor = subprocess.run(
            [str(script), "doctor", "--json"],
            check=True,
            cwd=venv_path,
            text=True,
            capture_output=True,
        )
        health = json.loads(doctor.stdout)
        assert health["effect_count"] >= 20
        assert health["schema_count"] >= 8
        assert health["schema_errors"] == []
        assert health["risk_rule_errors"] == []
        assert health["template_errors"] == []
        assert health["graph_node_count"] > health["command_count"]
        assert health["graph_errors"] == []
        assert health["ok"] is True

    schema_check = subprocess.run(
        [
            str(python),
            "-c",
            (
                "from ordin.schema import validate_schema_files; "
                "errors = validate_schema_files(); "
                "assert not errors, errors"
            ),
        ],
        check=True,
        cwd=venv_path,
        text=True,
        capture_output=True,
    )
    assert schema_check.returncode == 0
    assert outputs[0] == outputs[1]
