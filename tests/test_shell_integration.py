import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from commandgraph.cli import main
from commandgraph.shell_integration import render_shell_init


def test_bash_init_is_explicit_reversible_and_has_no_eval():
    script = render_shell_init("bash")
    assert "cgr()" in script
    assert "commandgraph_shell_disable()" in script
    assert "command bash -c" in script
    assert "eval " not in script
    assert "--cwd \"$PWD\"" in script
    assert "--interactive" in script


def test_zsh_init_includes_review_accept_widget_without_rebinding_enter():
    script = render_shell_init("zsh")
    assert "commandgraph-review-accept" in script
    assert "^X^G" in script
    assert "zle .accept-line" in script
    assert "commandgraph_shell_disable()" in script
    assert "eval " not in script
    assert "bindkey '^M'" not in script


def test_shell_init_cli_prints_script(capsys):
    assert main(["shell-init", "bash"]) == 0
    output = capsys.readouterr().out
    assert output == render_shell_init("bash")


def test_unsupported_shell_is_rejected():
    with pytest.raises(ValueError):
        render_shell_init("fish")


def _fake_commandgraph(path: Path, *, decision: str, exit_code: int) -> None:
    path.write_text(
        "#!/bin/sh\n"
        f"printf 'decision: {decision}\\nrisk: low\\n'\n"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_bash_wrapper_executes_allowed_exact_text(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _fake_commandgraph(bin_dir / "commandgraph", decision="allow", exit_code=0)
    init_file = tmp_path / "commandgraph.bash"
    init_file.write_text(render_shell_init("bash"), encoding="utf-8")

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        [
            bash,
            "-c",
            f"source {init_file}; cgr $'printf one\\nprintf two'",
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == "onetwo"


def test_bash_wrapper_does_not_execute_blocked_text(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _fake_commandgraph(bin_dir / "commandgraph", decision="block", exit_code=30)
    init_file = tmp_path / "commandgraph.bash"
    init_file.write_text(render_shell_init("bash"), encoding="utf-8")
    blocked_path = tmp_path / "must-not-exist"

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        [
            bash,
            "-c",
            f"source {init_file}; cgr 'touch {blocked_path}'",
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode == 30
    assert not blocked_path.exists()
    assert "decision: block" in result.stderr


def test_bash_generated_script_has_valid_syntax(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    init_file = tmp_path / "commandgraph.bash"
    init_file.write_text(render_shell_init("bash"), encoding="utf-8")
    subprocess.run([bash, "-n", str(init_file)], check=True)
