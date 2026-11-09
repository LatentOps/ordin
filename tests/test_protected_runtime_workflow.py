"""A required physical lane cannot pass with only skipped or missing positives."""

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest
import yaml

from scripts import check_protected_runtime as check
from scripts.release_integrity import RELEASE_WORKFLOW_CHECKS


def junit(tmp_path, *, change=None):
    root = ET.Element("testsuite", failures="0", errors="0")
    for name in sorted(check.REQUIRED_POSITIVES):
        ET.SubElement(root, "testcase", name=name)
    if change == "missing":
        root.remove(root.find("testcase"))
    elif change == "suite_error":
        root.set("errors", "1")
    elif change:
        ET.SubElement(root.find("testcase"), change)
    target = tmp_path / "junit.xml"
    ET.ElementTree(root).write(target)
    return target


def test_required_agent_and_pytest_positives_must_all_run(tmp_path):
    assert len(check.REQUIRED_POSITIVES) == 7
    assert set(check.qualify_junit(junit(tmp_path))) == check.REQUIRED_POSITIVES


@pytest.mark.parametrize("change", ["skipped", "failure", "error", "missing", "suite_error"])
def test_skipped_missing_failed_or_errored_physical_fixture_is_not_qualified(tmp_path, change):
    with pytest.raises(ValueError):
        check.qualify_junit(junit(tmp_path, change=change))


def test_actual_privileged_workflow_and_release_policy_require_both_versions():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/swarm-assurance.yml").read_text())
    job = workflow["jobs"]["protected-runtime"]
    versions = job["strategy"]["matrix"]["python"]
    assert versions == ["3.10", "3.13"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["env"]["ORDIN_REQUIRED_PROTECTED_PROCESS"] == "1"
    assert job["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert not job.get("continue-on-error") and "if" not in job
    invocation = next(
        step["run"] for step in job["steps"] if "check_protected_runtime.py" in step.get("run", "")
    )
    assert "sudo env" in invocation and "||" not in invocation
    required = {job["name"].replace("${{ matrix.python }}", version) for version in versions}
    assert required <= RELEASE_WORKFLOW_CHECKS["swarm-assurance.yml"]


def test_missing_root_capability_does_not_create_a_fake_positive_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "must-not-exist"
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(ValueError, match="privileged Linux"):
        check.main(["--workspace", str(workspace), "--revision", "a" * 40])
    assert not workspace.exists()
