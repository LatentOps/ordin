from commandgraph.shell import (
    command_substitutions,
    executable_name,
    split_shell_segments,
)


def test_compound_shell_is_segmented():
    segments, operators = split_shell_segments("lsof -i :3000 && rm -rf /")
    assert segments == [["lsof", "-i", ":3000"], ["rm", "-rf", "/"]]
    assert operators == ["&&"]


def test_newline_is_a_command_boundary():
    segments, operators = split_shell_segments("lsof -i :3000\nrm -rf /")
    assert segments == [["lsof", "-i", ":3000"], ["rm", "-rf", "/"]]
    assert operators == [";"]


def test_quoted_pipe_does_not_split_segment():
    segments, operators = split_shell_segments('echo "a | b" | head -n 1')
    assert segments == [["echo", "a | b"], ["head", "-n", "1"]]
    assert operators == ["|"]


def test_executable_name_unwraps_sudo():
    assert executable_name("sudo -u root rm -rf /") == "rm"


def test_executable_name_normalizes_python_module_execution():
    assert executable_name("python -m pip install requests") == "pip"


def test_command_substitution_is_extracted_inside_double_quotes():
    assert command_substitutions('echo "$(rm -rf /)"') == ["rm -rf /"]


def test_single_quote_inside_double_quotes_does_not_disable_substitution():
    assert command_substitutions('echo "it\'s $(rm -rf /)"') == ["rm -rf /"]


def test_command_substitution_is_ignored_inside_single_quotes():
    assert command_substitutions("echo '$(rm -rf /)'") == []
