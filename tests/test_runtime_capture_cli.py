"""Capture CLI migration is inert and does not create a process or report file."""

import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/capture_assurance_developer_experience.py"
SPEC = importlib.util.spec_from_file_location("runtime_capture_under_test", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def inert_capture(monkeypatch, *, failed_runtime=False):
    revision = "a" * 40
    passed = b'<testsuite><testcase name="bounded" classname="fixture"/></testsuite>'
    failed = (
        b'<testsuite><testcase name="bounded" classname="fixture"><failure/></testcase></testsuite>'
    )
    inputs = {
        "source.xml": passed,
        "host.xml": failed,
        "runtime.xml": failed if failed_runtime else passed,
        "wheel.json": json.dumps(
            {
                "smoke": {
                    "ok": True,
                    "offline_quickstart": {
                        "actions_executed": False,
                        "model_or_scanner_called": False,
                        "offline_finding_import": {"finding_confirmation": "not_performed"},
                    },
                }
            }
        ).encode(),
        "installed.json": json.dumps(
            {
                "schema_version": "ordin.runtime_integration_evaluation.v1",
                "revision": revision,
                "scope": {"cases": 17},
                "pass_count": 17,
                "failure_count": 0,
                "errors": [],
                "configuration": {"model_inference_used": False},
            }
        ).encode(),
    }
    writes, checks = [], []

    class MemoryReport(io.StringIO):
        def close(self):
            if not self.closed:
                writes.append(self.getvalue())
            super().close()

    class EvidencePath:
        def __init__(self, name):
            self.name = name

        def read_bytes(self):
            return inputs[self.name]

        def open(self, mode, *, encoding):
            assert self.name == "output.json" and mode == "x" and encoding == "utf-8"
            return MemoryReport()

    def no_process(arguments, **options):
        checks.append(arguments)
        assert arguments[:5] == ["rtk", "proxy", "git", "diff", "--quiet"]
        assert arguments[5] == revision
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(capture, "Path", EvidencePath)
    monkeypatch.setattr(capture.subprocess, "run", no_process)
    arguments = [
        "capture-runtime",
        "--revision",
        revision,
        "--source-junit",
        "source.xml",
        "--host-junit",
        "host.xml",
        "--wheel-check",
        "wheel.json",
        "--installed-runtime",
        "installed.json",
        "--output",
        "output.json",
    ]
    return arguments, writes, checks


@pytest.mark.parametrize("option", ["--runtime-junit", "--openshell-junit"])
def test_current_and_hidden_legacy_runtime_inputs_capture_truthful_inert_evidence(
    monkeypatch, capsys, option
):
    arguments, writes, checks = inert_capture(monkeypatch)
    monkeypatch.setattr("sys.argv", arguments + [option, "runtime.xml"])
    assert capture.main() == 0
    assert len(checks) == 1 and len(writes) == 1
    report = json.loads(writes[0])
    # These established report keys remain wire-compatible and are not re-signed.
    assert (
        report["openshell_gate"]["passed"] == 1
        and report["host_source_environment_gate"]["failed"] == 1
    )
    assert (
        report["installed_wheel_check"]["smoke"]["offline_quickstart"]["actions_executed"] is False
    )
    assert report["installed_runtime_check"]["configuration"]["model_inference_used"] is False
    assert json.loads(capsys.readouterr().out)["actions_executed"] is False


def test_capture_help_exposes_only_current_runtime_option(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["capture-runtime", "--help"])
    with pytest.raises(SystemExit) as stopped:
        capture.main()
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    assert "--runtime-junit" in help_text and "--openshell-junit" not in help_text


@pytest.mark.parametrize(
    "options", [[], ["--runtime-junit", "runtime.xml", "--openshell-junit", "runtime.xml"]]
)
def test_runtime_evidence_remains_required_and_unambiguous(monkeypatch, options):
    arguments, writes, checks = inert_capture(monkeypatch)
    monkeypatch.setattr("sys.argv", arguments + options)
    with pytest.raises(SystemExit) as stopped:
        capture.main()
    assert stopped.value.code == 2 and not checks and not writes


def test_failed_mandatory_runtime_gate_still_refuses_before_report(monkeypatch):
    arguments, writes, checks = inert_capture(monkeypatch, failed_runtime=True)
    monkeypatch.setattr("sys.argv", arguments + ["--runtime-junit", "runtime.xml"])
    with pytest.raises(ValueError, match="mandatory source/runtime gate failed"):
        capture.main()
    assert len(checks) == 1 and not writes
