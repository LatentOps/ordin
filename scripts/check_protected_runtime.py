"""Require installed-wheel agent and fixed-test kernel positives on privileged Linux."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TEST_FILES = (
    "tests/test_swarm_managed_process.py",
    "tests/test_swarm_confined_tests.py",
    "tests/test_swarm_runtime_catalog.py",
    "tests/test_swarm_owned_tests.py",
    "tests/test_swarm_owned_stop.py",
    "tests/test_swarm_owned_test_stop.py",
    "tests/test_swarm_owned_defaults.py",
    "integrations/swarm/tests/test_tool_host_profiles.py",
    "integrations/swarm/tests/test_tool_host_lineage.py",
    "integrations/swarm/tests/test_tool_host_protocol.py",
    "integrations/swarm/tests/test_tool_host_initialization.py",
    "integrations/swarm/tests/test_tool_host_tests.py",
    "integrations/swarm/tests/test_tool_host_test_wire.py",
    "integrations/swarm/tests/test_tool_host_uid_dispatch.py",
    "integrations/swarm/tests/test_tool_host_control_phase.py",
    "integrations/swarm/tests/test_tool_host_runtime_network.py",
    "integrations/swarm/tests/test_tool_host_cleanup.py",
    "integrations/swarm/tests/test_tool_host_cli.py",
    "integrations/swarm/tests/test_tool_host_commands.py",
    "integrations/swarm/tests/test_tool_host_deployment.py",
    "integrations/swarm/tests/test_tool_host_evaluation.py",
)
REQUIRED_POSITIVES = frozenset(
    {
        "test_new_owned_python_process_has_real_kernel_boundaries_and_no_host_environment",
        "test_private_child_channel_carries_only_bounded_mcp_data",
        "test_fixed_pytest_runs_only_after_kernel_readiness_and_ignores_repo_config",
        "test_untrusted_tests_cannot_bypass_kernel_or_access_broker_and_host",
        "test_installation_probe_does_not_execute_configured_project",
        "test_owned_test_timeout_is_unknown_without_retry",
        "test_catalog_restart_reverifies_same_identity_without_rebuild_or_code_execution",
        "test_catalog_build_pins_exact_linker_curation_and_materializes_stdlib_module_alias",
        "test_pinned_framework_outranks_real_project_pytest_py_and_private_package_shadows",
        "test_fixed_pytest_logging_and_caplog_use_only_private_quota_scratch",
        "test_original_confined_runner_result_is_aggregated_and_bound_to_its_job",
        "test_live_shared_host_init_handoff_exact_human_write_stop_and_epoch_restart",
        "test_actual_offline_two_agent_workflow_and_attack_suite[False]",
        "test_actual_offline_two_agent_workflow_and_attack_suite[True]",
    }
)


def qualify_junit(path: Path) -> list[str]:
    tree = ET.parse(path)
    if any(
        int(suite.get(key, "0")) != 0
        for suite in tree.iter()
        if suite.tag in {"testsuite", "testsuites"}
        for key in ("failures", "errors")
    ):
        raise ValueError("protected-runtime fixture suite reports a failure or error")
    cases = list(tree.iter("testcase"))
    if any(case.find("failure") is not None or case.find("error") is not None for case in cases):
        raise ValueError("protected-runtime fixture contains a failure or error")
    verified = []
    for name in sorted(REQUIRED_POSITIVES):
        selected = [
            case
            for case in cases
            if case.get("name") == name or case.get("name", "").startswith(name + "[")
        ]
        if not selected or any(case.find("skipped") is not None for case in selected):
            raise ValueError(
                "required actual protected-runtime positive missing or skipped: " + name
            )
        verified.append(name)
    return verified


def verify_wheel_bytes(core: Path, swarm: Path) -> dict[str, str]:
    pairs = [
        (core, ROOT, ROOT / "ordin"),
        (swarm, ROOT / "integrations/swarm", ROOT / "integrations/swarm/ordin_swarm"),
    ]
    checked = {}
    for wheel, base, directory in pairs:
        sources = list(directory.rglob("*.py"))
        if wheel is core:
            sources.extend((ROOT / "ordin/resources/schemas").glob("swarm-*.json"))
        with zipfile.ZipFile(wheel) as archive:
            for source in sorted(sources):
                relative = source.relative_to(base).as_posix()
                expected = source.read_bytes()
                if archive.read(relative) != expected:
                    raise ValueError(
                        "protected runtime wheel differs from exact source: " + relative
                    )
                checked[relative] = hashlib.sha256(expected).hexdigest()
    return checked


def copy_fixture_inputs(destination: Path) -> dict[str, str]:
    """Retain tracked helper/fixture paths while importing only installed packages."""
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "tests", "integrations/swarm/tests"], cwd=ROOT
    ).split(b"\0")
    checked = {}
    for raw in paths:
        if not raw:
            continue
        name = raw.decode("utf-8")
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not name.startswith(("tests/", "integrations/swarm/tests/"))
        ):
            raise ValueError("installed fixture input must remain in tracked test trees")
        source = ROOT / relative
        if source.is_symlink() or not source.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("installed fixture input cannot follow an external or linked source")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        checked[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    if not checked:
        raise ValueError("installed fixture dependencies are absent")
    package = destination / "tests/__init__.py"
    if not package.exists():
        package.write_text("")
    return checked


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args(argv)
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.uname().machine != "x86_64"
        or not re.fullmatch(r"[a-f0-9]{40}", args.revision)
    ):
        raise ValueError("required privileged Linux x86-64 installed fixture unavailable")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != args.revision:
        raise ValueError("protected-runtime source revision mismatch")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("protected-runtime source checkout must be clean")
    workspace = args.workspace.resolve()
    if workspace == ROOT or ROOT in workspace.parents:
        raise ValueError("installed fixture workspace must be outside the source checkout")
    workspace.mkdir(mode=0o700, exist_ok=False)
    wheels, evidence, copied = (workspace / name for name in ("wheels", "evidence", "tests"))
    for directory in (wheels, evidence, copied):
        directory.mkdir(mode=0o700)
    settings = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "ORDIN_REQUIRED_PROTECTED_PROCESS": "1",
        "ORDIN_REQUIRE_SWARM_BROKER": "1",
        "LANGCHAIN_TRACING_V2": "false",
        "LANGSMITH_TRACING": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for name in tuple(settings):
        if name.endswith(("API_KEY", "API_TOKEN")) or name == "PYTHONPATH":
            del settings[name]

    def run(command, *, cwd=workspace):
        subprocess.run(list(map(str, command)), cwd=cwd, env=settings, check=True)

    run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            wheels,
            ROOT,
            ROOT / "integrations/swarm",
        ]
    )
    core, swarm = next(wheels.glob("ordin-*.whl")), next(wheels.glob("ordin_swarm-*.whl"))
    parity = verify_wheel_bytes(core, swarm)
    environment = workspace / "env"
    run([sys.executable, "-m", "venv", environment])
    python = environment / "bin/python"
    settings["PATH"] = str(python.parent) + ":/usr/local/bin:/usr/bin:/bin"
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            ROOT / "requirements/dev-baseline.txt",
        ]
    )
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-build-isolation",
            str(core) + "[assurance-dev]",
            str(swarm) + "[test-runtime]",
        ]
    )
    run([python, "-m", "pip", "check"])
    origin_code = (
        "from pathlib import Path; import ordin,ordin_swarm; "
        "root=Path.cwd(); assert not Path(ordin.__file__).is_relative_to(" + repr(str(ROOT)) + "); "
        "assert not Path(ordin_swarm.__file__).is_relative_to(" + repr(str(ROOT)) + "); "
        "print('installed protected-runtime origins',ordin.__file__,ordin_swarm.__file__)"
    )
    run([python, "-I", "-c", origin_code])
    entrypoint_code = (
        "from importlib.metadata import distribution; "
        "entry=next(e for e in distribution('ordin-swarm').entry_points "
        "if e.group=='console_scripts' and e.name=='ordin-swarm-host'); "
        "assert entry.value=='ordin_swarm.host_cli:entrypoint'; print(entry.value)"
    )
    run([python, "-I", "-c", entrypoint_code])
    console = environment / "bin/ordin-swarm-host"
    run([console, "--help"])
    run([python, "-I", "-m", "ordin_swarm.host_cli", "--help"])
    inputs = copy_fixture_inputs(copied)
    if any(not (copied / name).is_file() for name in TEST_FILES):
        raise ValueError("required installed runtime or host fixture file is missing")
    junit = evidence / "junit.xml"
    run(
        [
            python,
            "-I",
            "-B",
            "-m",
            "pytest",
            "-q",
            "-W",
            "error::pytest.PytestUnhandledThreadExceptionWarning",
            *[copied / name for name in TEST_FILES],
            "--basetemp",
            workspace / "pytest-temp",
            "--junitxml",
            junit,
        ]
    )
    verified = qualify_junit(junit)
    if (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != actual
        or subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip()
    ):
        raise ValueError("protected-runtime source changed during installed qualification")
    report = {
        "revision": actual,
        "installed_wheel": True,
        "required_actual_positives": verified,
        "source_wheel_sha256": parity,
        "wheels_sha256": {
            wheel.name: hashlib.sha256(wheel.read_bytes()).hexdigest() for wheel in (core, swarm)
        },
        "tests_sha256": {
            name: hashlib.sha256((copied / name).read_bytes()).hexdigest() for name in TEST_FILES
        },
        "fixture_inputs_sha256": inputs,
        "installed_console": str(console),
        "installed_console_target": "ordin_swarm.host_cli:entrypoint",
        "installed_module_help_passed": True,
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "pytest_junit": str(junit),
        "scope": "finite privileged Linux agent, aggregate, human workflow and host fixtures; test diagnostics are not execution authority",
    }
    (evidence / "protected-runtime.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
