"""A required physical lane cannot pass with only skipped or missing positives."""

from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

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
    assert len(check.REQUIRED_POSITIVES) == 14
    assert set(check.qualify_junit(junit(tmp_path))) == check.REQUIRED_POSITIVES


@pytest.mark.parametrize("change", ["skipped", "failure", "error", "missing", "suite_error"])
def test_skipped_missing_failed_or_errored_physical_fixture_is_not_qualified(tmp_path, change):
    with pytest.raises(ValueError):
        check.qualify_junit(junit(tmp_path, change=change))


def test_non_enhanced_workflow_cannot_substitute_for_required_protected_human_test_flow(tmp_path):
    target = junit(tmp_path)
    tree = ET.parse(target)
    root = tree.getroot()
    enhanced = next(
        case
        for case in root
        if case.get("name") == "test_actual_offline_two_agent_workflow_and_attack_suite[True]"
    )
    root.remove(enhanced)
    tree.write(target)
    with pytest.raises(ValueError, match="attack_suite\\[True\\]"):
        check.qualify_junit(target)


def test_installed_input_copy_retains_helper_and_fixture_trees_without_source_packages(
    tmp_path, monkeypatch
):
    source, copied = tmp_path / "source", tmp_path / "copied"
    paths = (
        "tests/helpers.py",
        "tests/fixtures/swarm_tls/ca.pem",
        "integrations/swarm/tests/test_tool_host_profiles.py",
    )
    for name in paths:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    monkeypatch.setattr(check, "ROOT", source)
    monkeypatch.setattr(
        check.subprocess,
        "check_output",
        lambda *args, **kwargs: b"\0".join(p.encode() for p in paths),
    )
    assert set(check.copy_fixture_inputs(copied)) == set(paths)
    assert (copied / "tests/__init__.py").is_file()
    assert not (copied / "ordin").exists() and not (copied / "ordin_swarm").exists()
    for name in paths:
        assert (copied / name).read_bytes() == (source / name).read_bytes()


@pytest.mark.parametrize("name", ["ordin/__init__.py", "tests/../../escape.py"])
def test_installed_input_copy_refuses_package_or_parent_escape_paths(tmp_path, monkeypatch, name):
    monkeypatch.setattr(check, "ROOT", tmp_path)
    monkeypatch.setattr(check.subprocess, "check_output", lambda *args, **kwargs: name.encode())
    with pytest.raises(ValueError, match="tracked test trees"):
        check.copy_fixture_inputs(tmp_path / "copied")


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


def test_installed_parity_covers_core_credential_and_runtime_boundaries(tmp_path, monkeypatch):
    source = tmp_path / "source"
    core_files = (
        "ordin/agent.py",
        "ordin/session.py",
        "ordin/assurance/delegating_gate.py",
        "ordin/runtime_requirements.py",
        "ordin/swarm/managed_process.py",
        "ordin/resources/schemas/swarm-fixture.json",
    )
    optional = "ordin_swarm/__init__.py"
    for name in (*core_files, "integrations/swarm/" + optional):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((name + " exact bytes").encode())
    core, swarm = tmp_path / "ordin.whl", tmp_path / "ordin_swarm.whl"
    with zipfile.ZipFile(core, "w") as archive:
        for name in core_files:
            archive.writestr(name, (source / name).read_bytes())
    with zipfile.ZipFile(swarm, "w") as archive:
        archive.writestr(optional, (source / "integrations/swarm" / optional).read_bytes())
    monkeypatch.setattr(check, "ROOT", source)
    assert set(check.verify_wheel_bytes(core, swarm)) == {*core_files, optional}
    (source / "ordin/agent.py").write_bytes(b"different credential boundary")
    with pytest.raises(ValueError, match="differs from exact source"):
        check.verify_wheel_bytes(core, swarm)
