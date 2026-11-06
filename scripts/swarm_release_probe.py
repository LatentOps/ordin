"""Fixed installed-wheel probes used only by check_swarm_release.py."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from importlib import import_module
from importlib.util import find_spec
from importlib.resources import files
import io
import json
import os
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    "mcp": ("tests/test_swarm_gateway_adapters.py", "-k", "not maintained_hooks"),
    "hooks": ("tests/test_swarm_gateway_adapters.py", "-k", "maintained_hooks"),
    "coordinator_restart": (
        "tests/test_swarm_coordinator_recovery.py::test_takeover_fences_old_owner_and_retains_uncertain_budget",
        "tests/test_swarm_coordinator_recovery.py::test_revocation_survives_restart_and_json_cannot_resume",
    ),
    "multi_host_epochs": (
        "tests/test_swarm_coordinator.py::test_two_authenticated_hosts_cannot_reserve_past_shared_swarm_budget",
        "tests/test_swarm_coordinator_recovery.py::test_epoch_change_during_backend_reconciliation_cannot_resume",
        "tests/test_swarm_delegation.py::test_unused_admission_cannot_survive_changed_current_state",
    ),
}


def pin(name):
    package = import_module(name)
    path = Path(package.__file__).resolve(strict=True)
    if not path.is_relative_to(Path(sys.prefix).resolve()) or "site-packages" not in path.parts:
        raise ValueError("release probes require an isolated installed wheel")
    return path.parent


def verify_loaded(roots):
    for name, module in tuple(sys.modules.items()):
        for namespace, root in roots.items():
            if module is not None and (name == namespace or name.startswith(namespace + ".")):
                path = getattr(module, "__file__", None)
                if path is None or not Path(path).resolve().is_relative_to(root):
                    raise ValueError("source overlay entered an installed namespace")


class Capture(io.StringIO):
    def write(self, value):
        remaining = max(0, 1048576 - self.tell())
        super().write(value[:remaining])
        return len(value)


def core_compatibility():
    from unittest.mock import patch
    import socket
    import subprocess

    def refused(*args, **kwargs):
        raise AssertionError("core import/review attempted process or network execution")

    with (
        patch.object(socket.socket, "bind", refused),
        patch.object(socket.socket, "connect", refused),
        patch.object(subprocess, "Popen", refused),
    ):
        import ordin
        import ordin.swarm
        from ordin import ActionEnvelope, AgentGate
        from ordin.schema import SCHEMA_FILES

        verify_loaded({"ordin": pin("ordin")})

        frozen = json.loads(
            files("ordin").joinpath("resources/public-surface-0.3.json").read_text()
        )
        assert set(frozen["exports"]) <= set(ordin.__all__)
        assert set(frozen["schemas"]) <= set(SCHEMA_FILES)
        gate = AgentGate()
        assert gate.evaluate_action(ActionEnvelope.shell("git status --short")).may_execute
        assert gate.evaluate_action(ActionEnvelope.shell("rm -rf /")).denied
        assert not gate.evaluate_action(ActionEnvelope("future", "opaque", {})).may_execute
        assert find_spec("ordin_swarm") is None
        assert all(
            find_spec(name) is None
            for name in ("openai", "langgraph", "crewai", "autogen_core", "psycopg")
        )
    return {
        "schema_version": "ordin.swarm_release_check.v1",
        "id": "core_compatibility",
        "passed": 6,
        "failed": 0,
        "skipped": 0,
        "source_overlay": False,
        "namespace_origin": "isolated_wheels",
        "network_or_process_execution": False,
        "v0_3_surface_preserved": True,
        "physical_enforcement": False,
        "execution_authority": False,
    }


def regression(group, temporary, fixture_root):
    roots = {name: pin(name) for name in ("ordin", "ordin_swarm")}
    import pytest

    counts = {"passed": 0, "failed": 0, "skipped": 0, "collected": 0}

    class Summary:
        def pytest_collection_finish(self, session):
            counts["collected"] = len(session.items)

        def pytest_runtest_logreport(self, report):
            if report.failed:
                counts["failed"] += 1
            elif report.skipped:
                counts["skipped"] += 1
            elif report.when == "call" and report.passed:
                counts["passed"] += 1

        def pytest_collectreport(self, report):
            if report.failed:
                counts["failed"] += 1

    arguments = []
    for name in GROUPS[group]:
        arguments.append(str(fixture_root / name) if name.startswith("tests/") else name)
    captured = Capture()
    with redirect_stdout(captured), redirect_stderr(captured):
        result = pytest.main(
            [
                "-q",
                "-p",
                "no:cacheprovider",
                "--confcutdir=" + str(fixture_root / "tests"),
                "--basetemp=" + str(temporary),
                *arguments,
            ],
            plugins=[Summary()],
        )
    verify_loaded(roots)
    if result:
        descriptor = os.open(
            temporary.parent / ("private-" + group + ".log"),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(captured.getvalue())
    return {
        "schema_version": "ordin.swarm_release_check.v1",
        "id": group,
        **counts,
        "exit_code": int(result),
        "namespace_origin": "isolated_wheels",
        "source_overlay": False,
        "diagnostics_omitted": True,
        "diagnostics_sha256": hashlib.sha256(captured.getvalue().encode()).hexdigest(),
        "fixture_kind": "owned_synthetic_protocol_checks",
        "physical_enforcement": False,
        "execution_authority": False,
    }


def environment():
    roots = {name: pin(name) for name in ("ordin", "ordin_swarm")}
    verify_loaded(roots)
    return {
        "schema_version": "ordin.swarm_release_environment.v1",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": sys.platform,
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count() or 1,
        "package_origin": "isolated_wheels",
        "optional_risk_module_installed": find_spec("ordin.swarm.risk_signals") is not None,
        "optional_risk_configured": False,
        "hosted_model_providers_installed": any(
            find_spec(name) is not None
            for name in ("openai", "anthropic", "langgraph", "crewai", "autogen_core")
        ),
        "llm_inference_exercised": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=("core_compatibility", "environment", "manifest", *GROUPS))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--basetemp", type=Path)
    parser.add_argument("--fixtures-root", type=Path)
    parser.add_argument("--inputs", type=Path)
    args = parser.parse_args()
    if args.group == "core_compatibility":
        report = core_compatibility()
    elif args.group == "environment":
        report = environment()
    elif args.group == "manifest":
        if args.inputs is None:
            parser.error("manifest collection requires fixed producer inputs")
        roots = {name: pin(name) for name in ("ordin", "ordin_swarm")}
        from ordin_swarm._release_collect import collect

        report = collect(args.inputs, args.output.parent)
        verify_loaded(roots)
    else:
        if args.basetemp is None or args.fixtures_root is None:
            parser.error("regression fixtures require an explicit owned basetemp")
        fixture_root = args.fixtures_root.resolve(strict=True)
        workspace = args.output.parent.parent.resolve(strict=True)
        temporary = args.basetemp.resolve()
        if (
            args.output.parent.name != "evidence"
            or fixture_root != workspace / "fixtures"
            or temporary != workspace / ("pytest-" + args.group)
            or temporary.exists()
            or temporary.is_symlink()
        ):
            parser.error("regressions require the fresh owned versioned fixture archive")
        report = regression(args.group, temporary, fixture_root)
    descriptor = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    return 0 if not report.get("failed") and not report.get("exit_code") else 1


if __name__ == "__main__":
    raise SystemExit(main())
