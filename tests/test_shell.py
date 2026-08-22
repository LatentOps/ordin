from commandgraph.shell import executable_name, split_shell_segments


def test_compound_shell_is_segmented():
    segments, operators = split_shell_segments("lsof -i :3000 && rm -rf /")
    assert segments == [["lsof", "-i", ":3000"], ["rm", "-rf", "/"]]
    assert operators == ["&&"]


def test_quoted_pipe_does_not_split_segment():
    segments, operators = split_shell_segments('echo "a | b" | head -n 1')
    assert segments == [["echo", "a | b"], ["head", "-n", "1"]]
    assert operators == ["|"]


def test_executable_name_unwraps_sudo():
    assert executable_name("sudo -u root rm -rf /") == "rm"


def test_executable_name_normalizes_python_module_execution():
    assert executable_name("python -m pip install requests") == "pip"
