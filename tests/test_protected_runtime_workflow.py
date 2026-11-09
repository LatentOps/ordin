"""A required physical lane cannot pass with only skipped or missing positives."""

import builtins
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import zipfile

import pytest

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
    yaml = pytest.importorskip("yaml")
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
        step["run"] for step in job["steps"] if "run_protected_runtime_ci.py" in step.get("run", "")
    )
    assert "sudo /usr/bin/env -i" in invocation and "||" not in invocation
    assert "/usr/bin/python3 -I -S -B" in invocation and "--capture-selected" in invocation
    assert '--private-root "/root/' in invocation and "--runner-uid" in invocation
    required = {job["name"].replace("${{ matrix.python }}", version) for version in versions}
    assert required <= RELEASE_WORKFLOW_CHECKS["swarm-assurance.yml"]


def test_missing_root_capability_does_not_create_a_fake_positive_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "must-not-exist"
    monkeypatch.setattr(check.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(ValueError, match="privileged Linux"):
        check.main(["--workspace", str(workspace), "--revision", "a" * 40])
    assert not workspace.exists()


def wheel_fixture(tmp_path, monkeypatch, *, renamed=False):
    source = tmp_path / "source"
    package = "renamed_core" if renamed else "ordin"
    optional = "renamed_swarm" if renamed else "ordin_swarm"
    core_files = {
        f"{package}/{name}": (name + " exact bytes").encode()
        for name in (
            "__init__.py",
            "agent.py",
            "session.py",
            "assurance/__init__.py",
            "assurance/delegating_gate.py",
            "runtime_requirements.py",
            "swarm/__init__.py",
            "swarm/managed_process.py",
            "resources/risk_rules.json",
            "resources/schemas/swarm-fixture.json",
            "resources/schemas/runtime-fixture.json",
            "resources/swarm/tls/ca.pem",
            "resources/swarm/tls/README.md",
            "resources/codex_security/LICENSE.upstream",
            "plugin_assets/brand/.codex-plugin/plugin.json",
            "plugin_assets/brand/hooks/hooks.json",
            "plugin_assets/brand/scripts/hook.py",
        )
    }
    swarm_files = {
        f"{optional}/{name}": (name + " exact bytes").encode()
        for name in (
            "__init__.py",
            "host_runtime.py",
            "migrations/0001-coordinator.sql",
            "migrations/README.md",
        )
    }
    inputs = {
        **core_files,
        **{"integrations/swarm/" + name: data for name, data in swarm_files.items()},
        "LICENSE": b"exact license\n",
        "NOTICE": b"exact notice\n",
    }
    inputs["pyproject.toml"] = f'''[project]
name = "{package.replace("_", "-")}"
version = "0.4.0.dev0"
[tool.setuptools]
packages = ["{package}", "{package}.assurance", "{package}.swarm"]
[tool.setuptools.package-data]
{package} = ["resources/*.json", "resources/**/*.json", "resources/swarm/tls/*.pem", "resources/swarm/tls/*.md", "resources/codex_security/LICENSE.upstream", "plugin_assets/brand/.codex-plugin/*.json", "plugin_assets/brand/hooks/*.json", "plugin_assets/brand/scripts/*.py"]
'''.encode()
    inputs["integrations/swarm/pyproject.toml"] = f'''[project]
name = "{optional.replace("_", "-")}"
version = "0.4.0.dev0"
[tool.setuptools.packages.find]
include = ["{optional}*"]
namespaces = false
[tool.setuptools.package-data]
{optional} = ["migrations/*.sql", "migrations/*.md"]
'''.encode()
    for name, data in inputs.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    tracked = list(inputs)
    monkeypatch.setattr(check, "ROOT", source)
    monkeypatch.setattr(
        check.subprocess,
        "check_output",
        lambda *a, **k: b"\0".join(name.encode() for name in tracked),
    )

    def metadata(name):
        prefix = name + "-0.4.0.dev0.dist-info/"
        return {
            prefix + name: data
            for name, data in {
                "METADATA": f"Metadata-Version: 2.4\nName: {name.replace('_', '-')}\nVersion: 0.4.0.dev0\n".encode(),
                "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                "RECORD": b"",
                "entry_points.txt": b"[console_scripts]\n",
                "top_level.txt": name.encode(),
            }.items()
        }

    members = [
        {
            **core_files,
            **metadata(package),
            f"{package}-0.4.0.dev0.dist-info/licenses/LICENSE": inputs["LICENSE"],
            f"{package}-0.4.0.dev0.dist-info/licenses/NOTICE": inputs["NOTICE"],
        },
        {**swarm_files, **metadata(optional)},
    ]
    wheels = [tmp_path / "core.whl", tmp_path / "optional.whl"]
    for path, entries in zip(wheels, members):
        write_wheel(path, entries)
    return SimpleNamespace(
        source=source,
        wheels=wheels,
        members=members,
        tracked=tracked,
        core=package,
        swarm=optional,
        payload={**core_files, **swarm_files},
    )


def write_wheel(path, members):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


@pytest.mark.parametrize("renamed", [False, True])
def test_installed_parity_covers_declared_code_resources_and_tracked_license_bytes(
    tmp_path, monkeypatch, renamed
):
    fixture = wheel_fixture(tmp_path, monkeypatch, renamed=renamed)
    observed = check.verify_wheel_bytes(*fixture.wheels)
    assert set(observed) == set(fixture.payload) | {
        f"{fixture.core}-0.4.0.dev0.dist-info/licenses/LICENSE",
        f"{fixture.core}-0.4.0.dev0.dist-info/licenses/NOTICE",
    }
    (fixture.source / fixture.core / "agent.py").write_bytes(b"different credential boundary")
    with pytest.raises(ValueError, match="differs from exact source"):
        check.verify_wheel_bytes(*fixture.wheels)


@pytest.mark.parametrize(
    "wheel,relative",
    [
        (0, "ordin/resources/risk_rules.json"),
        (0, "ordin/resources/schemas/runtime-fixture.json"),
        (0, "ordin/resources/swarm/tls/ca.pem"),
        (0, "ordin/plugin_assets/brand/.codex-plugin/plugin.json"),
        (0, "ordin/plugin_assets/brand/scripts/hook.py"),
        (0, "ordin-0.4.0.dev0.dist-info/licenses/LICENSE"),
        (0, "ordin-0.4.0.dev0.dist-info/licenses/NOTICE"),
        (1, "ordin_swarm/migrations/0001-coordinator.sql"),
        (1, "ordin_swarm/migrations/README.md"),
    ],
)
@pytest.mark.parametrize("change", ["missing", "changed"])
def test_missing_or_changed_packaged_resource_cannot_qualify(
    tmp_path, monkeypatch, wheel, relative, change
):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    if change == "missing":
        del fixture.members[wheel][relative]
    else:
        fixture.members[wheel][relative] = b"stale resource bytes"
    write_wheel(fixture.wheels[wheel], fixture.members[wheel])
    with pytest.raises(ValueError, match="inventory differs|differs from exact source"):
        check.verify_wheel_bytes(*fixture.wheels)


@pytest.mark.parametrize(
    "wheel,extra",
    [
        (0, "ordin/stale_untracked.py"),
        (1, "ordin_swarm/stale_untracked.py"),
        (0, "ordin/agent.pyd"),
        (0, "unexpected.pth"),
        (1, "foreign/__init__.py"),
        (1, "foreign-1.0.dist-info/RECORD"),
        (1, "ordin_swarm-0.4.0.dev0.dist-info/EXTRA.py"),
        (1, "ordin_swarm-0.4.0.dev0.data/scripts/untrusted"),
        (1, "ordin_swarm/../outside.py"),
    ],
)
def test_extra_package_metadata_or_data_payload_cannot_qualify(tmp_path, monkeypatch, wheel, extra):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    fixture.members[wheel][extra] = b"not in exact tracked package inputs"
    write_wheel(fixture.wheels[wheel], fixture.members[wheel])
    with pytest.raises(ValueError, match="inventory differs|regular relative"):
        check.verify_wheel_bytes(*fixture.wheels)


def test_matching_untracked_source_file_does_not_expand_package_inventory(tmp_path, monkeypatch):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    relative = "ordin/resources/untracked.json"
    (fixture.source / relative).write_bytes(b"{}")
    fixture.members[0][relative] = b"{}"
    write_wheel(fixture.wheels[0], fixture.members[0])
    with pytest.raises(ValueError, match="inventory differs"):
        check.verify_wheel_bytes(*fixture.wheels)


def test_a_missing_tracked_package_input_cannot_disappear_from_inventory(tmp_path, monkeypatch):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    (fixture.source / "ordin/resources/risk_rules.json").unlink()
    with pytest.raises(ValueError, match="regular contained file"):
        check.verify_wheel_bytes(*fixture.wheels)


@pytest.mark.parametrize("kind", [0o120000, 0o010000])
def test_existing_wheel_member_cannot_substitute_a_link_or_special_file(
    tmp_path, monkeypatch, kind
):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    with zipfile.ZipFile(fixture.wheels[0], "w") as archive:
        for name, data in fixture.members[0].items():
            entry = zipfile.ZipInfo(name)
            if name == "ordin/agent.py":
                entry.external_attr = (kind | 0o644) << 16
            archive.writestr(entry, data)
    with pytest.raises(ValueError, match="regular relative file"):
        check.verify_wheel_bytes(*fixture.wheels)


def test_duplicate_wheel_paths_are_not_hidden_by_zip_lookup(tmp_path, monkeypatch):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(fixture.wheels[0], "a") as archive:
            archive.writestr("ordin/agent.py", fixture.members[0]["ordin/agent.py"])
    with pytest.raises(ValueError, match="duplicate"):
        check.verify_wheel_bytes(*fixture.wheels)


@pytest.mark.parametrize("field,value", [("Name", "foreign"), ("Version", "0.1.0")])
def test_generated_metadata_must_identify_the_declared_distribution(
    tmp_path, monkeypatch, field, value
):
    fixture = wheel_fixture(tmp_path, monkeypatch)
    relative = "ordin-0.4.0.dev0.dist-info/METADATA"
    text = fixture.members[0][relative].decode()
    original = "ordin" if field == "Name" else "0.4.0.dev0"
    fixture.members[0][relative] = text.replace(
        f"{field}: {original}", f"{field}: {value}"
    ).encode()
    write_wheel(fixture.wheels[0], fixture.members[0])
    with pytest.raises(ValueError, match="metadata identity"):
        check.verify_wheel_bytes(*fixture.wheels)


@pytest.mark.parametrize(
    "name,pattern,expected",
    [
        ("resources/a.json", "resources/*.json", True),
        ("resources/nested/a.json", "resources/*.json", False),
        ("resources/a.json", "resources/**/*.json", True),
        ("resources/a/b/c.json", "resources/**/*.json", True),
        ("NOTICE", "NOTICE*", True),
        ("somewhere/NOTICE", "NOTICE*", False),
    ],
)
def test_declared_resource_globs_keep_setuptools_directory_boundaries(name, pattern, expected):
    assert check._glob_matches(name, pattern) is expected


def origin_fixture(tmp_path):
    environment = tmp_path / "fresh-environment"
    site = environment / "lib/python/site-packages"
    modules = {name: site / name / "__init__.py" for name in ("ordin", "ordin_swarm")}
    for path in modules.values():
        path.parent.mkdir(parents=True)
        path.write_text("# origin fixture, never imported\n")
    return environment, site, {name: str(path) for name, path in modules.items()}


def test_origins_must_resolve_inside_the_fresh_interpreters_site_packages(tmp_path):
    environment, site, origins = origin_fixture(tmp_path)
    check.verify_installed_origins(environment, str(environment), (str(site),), origins)
    outside = tmp_path / "other-environment" / "ordin.py"
    outside.parent.mkdir()
    outside.write_text("# outside the checkout but not the fresh environment\n")
    with pytest.raises(ValueError, match="imports must be inside"):
        check.verify_installed_origins(
            environment, str(environment), (str(site),), {**origins, "ordin": str(outside)}
        )


@pytest.mark.parametrize("change", ["prefix", "site", "site_is_prefix", "missing_module"])
def test_incomplete_or_foreign_environment_origin_evidence_cannot_qualify(tmp_path, change):
    environment, site, origins = origin_fixture(tmp_path)
    prefix = str(tmp_path if change == "prefix" else environment)
    sites = (
        str(tmp_path if change == "site" else environment if change == "site_is_prefix" else site),
    )
    if change == "missing_module":
        del origins["ordin_swarm"]
    with pytest.raises(ValueError, match="fresh environment"):
        check.verify_installed_origins(environment, prefix, sites, origins)


def test_python310_collector_uses_the_locked_tomli_fallback(monkeypatch):
    fallback = SimpleNamespace(__name__="tomli", loads=check.tomllib.loads)
    monkeypatch.setitem(sys.modules, "tomllib", None)
    monkeypatch.setitem(sys.modules, "tomli", fallback)
    loaded = runpy.run_path(check.__file__, run_name="protected_runtime_tomli_probe")
    assert loaded["tomllib"] is fallback
    assert loaded["tomllib"].loads('[project]\nname="fixture"')["project"]["name"] == "fixture"


@pytest.mark.parametrize("outside", [False, True])
def test_the_exact_isolated_origin_probe_checks_fresh_environment_membership(tmp_path, outside):
    environment, site, origins = origin_fixture(tmp_path)
    if outside:
        other = tmp_path / "old-ordin.py"
        other.write_text("# outside the checkout and the fresh environment\n")
        origins["ordin"] = str(other)
    imported = {
        "sys": SimpleNamespace(prefix=str(environment)),
        "sysconfig": SimpleNamespace(get_path=lambda name: str(site)),
        **{name: SimpleNamespace(__file__=origin) for name, origin in origins.items()},
    }

    def fake_import(name, *args, **kwargs):
        if name in imported:
            return imported[name]
        return builtins.__import__(name, *args, **kwargs)

    scope = {"__builtins__": {**vars(builtins), "__import__": fake_import}}
    if outside:
        with pytest.raises(ValueError, match="imports must be inside"):
            exec(check._installed_origin_probe(environment), scope)
    else:
        exec(check._installed_origin_probe(environment), scope)
