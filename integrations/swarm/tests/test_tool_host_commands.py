"""Actual module CLI lifecycle outside source; no paid services or model APIs."""

import json
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

pytest.importorskip("ordin_swarm")

from test_tool_host_profiles import document


@pytest.mark.skipif(sys.platform != "linux", reason="actual private Linux deployment required")
def test_cli_init_serve_doctor_config_operator_stop_and_explicit_restart(tmp_path):
    root = tmp_path / "cli-installation"
    selection = tmp_path / "profile.json"
    selection.write_text(json.dumps(document(root)), encoding="utf-8")
    source = tmp_path / "input.txt"
    secret = "CLI fixture private document must never appear in public logs"
    source.write_text(secret, encoding="utf-8")
    settings = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "LANGCHAIN_TRACING_V2": "false",
        "LANGSMITH_TRACING": "false",
        "OTEL_SDK_DISABLED": "true",
    }
    base = [sys.executable, "-B", "-m", "ordin_swarm.host_cli"]

    def command(*arguments):
        result = subprocess.run(
            [*base, *arguments],
            cwd=tmp_path,
            env=settings,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=40,
            check=False,
        )
        assert secret.encode() not in result.stdout + result.stderr
        return result

    initialized = command(
        "init",
        "--directory",
        str(root),
        "--profile",
        str(selection),
        "--input",
        "document.txt=" + str(source),
    )
    assert initialized.returncode == 0, initialized.stderr
    assert json.loads(initialized.stdout)["status"] == "initialized"
    assert (
        command(
            "init",
            "--directory",
            str(root),
            "--profile",
            str(selection),
            "--input",
            "document.txt=" + str(source),
        ).returncode
        == 2
    )
    assert command("doctor", "--directory", str(root)).returncode == 0

    def serve(epoch, flag):
        process = subprocess.Popen(
            [
                *base,
                "serve",
                "--directory",
                str(root),
                "--port",
                "0",
                "--policy-epoch",
                str(epoch),
                flag,
            ],
            cwd=tmp_path,
            env=settings,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert process.stdout is not None
            ready, _, _ = select.select([process.stdout], [], [], 40)
            assert ready, "bounded CLI daemon startup did not report readiness"
            line = process.stdout.readline(4097)
            assert line.endswith(b"\n") and len(line) <= 4096
            assert json.loads(line)["status"] == "listening"
            return process
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            raise

    for epoch, mode in ((0, "--initialize-scope"), (1, "--takeover")):
        process = serve(epoch, mode)
        try:
            live = command("doctor", "--directory", str(root), "--live", "--actor", "reader")
            assert live.returncode == 0 and json.loads(live.stdout)["online_verified"] is True
            output = tmp_path / ("reader-" + str(epoch) + ".json")
            assert (
                command(
                    "client-config",
                    "--directory",
                    str(root),
                    "--actor",
                    "reader",
                    "--output",
                    str(output),
                ).returncode
                == 0
            )
            configuration = json.loads(output.read_text())
            assert configuration["mcpServers"]["ordin-reader"]["command"] == sys.executable
            assert "BEGIN PRIVATE KEY" not in output.read_text()
            queued = command("operator", "--directory", str(root), "queue")
            assert queued.returncode == 0 and json.loads(queued.stdout)["data"]["requests"] == []
            stopped = command("operator", "--directory", str(root), "stop")
            assert stopped.returncode in {0, 2}  # A final TLS reply can race close.
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0 and secret.encode() not in stdout + stderr
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if epoch == 0:
            same_epoch = command(
                "serve",
                "--directory",
                str(root),
                "--port",
                "0",
                "--policy-epoch",
                "0",
                "--takeover",
            )
            assert same_epoch.returncode == 2
            assert command("doctor", "--directory", str(root), "--live").returncode == 2
    assert Path(source).read_text() == secret
