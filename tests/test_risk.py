from commandgraph.risk import check_command


def test_chmod_777_warns_high():
    review = check_command("chmod -R 777 .")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert review.as_dict()["schema_version"] == "commandgraph.risk_review.v1"
    assert "chmod_recursive" in review.as_dict()["matched_rules"]


def test_root_delete_blocks():
    review = check_command("rm -rf /")
    assert review.decision == "block"
    assert review.risk == "critical"
    assert "root_filesystem_mutation" in review.as_dict()["risk_categories"]


def test_root_glob_delete_blocks():
    review = check_command("rm -rf /*")
    assert review.decision == "block"
    assert review.risk == "critical"


def test_readonly_command_allows():
    review = check_command("lsof -i :3000")
    assert review.decision == "allow"
    assert review.risk == "low"


def test_secret_file_warns():
    review = check_command("cat .env")
    assert review.decision == "warn"
    assert review.risk == "medium"
    assert "secret_exposure" in review.as_dict()["risk_categories"]


def test_empty_command_blocks():
    review = check_command("")
    assert review.decision == "block"
    assert review.risk == "critical"


def test_package_install_warns():
    review = check_command("python -m pip install requests")
    assert review.decision == "warn"
    assert "package_install" in review.as_dict()["risk_categories"]


def test_docker_prune_warns_high():
    review = check_command("docker system prune -a")
    assert review.decision == "warn"
    assert review.risk == "high"


def test_unknown_command_asks_instead_of_allowing():
    review = check_command("definitely-not-a-command --destroy")
    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert "unclassified_command" in review.as_dict()["risk_categories"]


def test_risky_segment_raises_compound_command_decision():
    review = check_command("lsof -i :3000 && rm -rf /")
    assert review.decision == "block"
    assert review.risk == "critical"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_newline_separates_commands_for_review():
    review = check_command("lsof -i :3000\nrm -rf /")
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_download_piped_to_shell_warns_high():
    review = check_command("curl https://example.com/install.sh | bash")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "curl_shell" in review.as_dict()["matched_rules"]


def test_shell_c_payload_is_reviewed_recursively():
    review = check_command("bash -c 'rm -rf /'")
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_grouped_subshell_is_reviewed_recursively():
    review = check_command("(rm -rf /)")
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_command_substitution_is_reviewed_recursively():
    review = check_command("echo $(rm -rf /)")
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_command_substitution_inside_double_quotes_is_reviewed():
    review = check_command('echo "$(rm -rf /)"')
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_legacy_backtick_substitution_is_reviewed():
    review = check_command("echo `rm -rf /`")
    assert review.decision == "block"
    assert "root_delete" in review.as_dict()["matched_rules"]


def test_single_quoted_command_substitution_is_not_executed():
    review = check_command("echo '$(rm -rf /)'")
    assert review.decision != "block"
    assert "root_delete" not in review.as_dict()["matched_rules"]


def test_single_quoted_backtick_substitution_is_not_executed():
    review = check_command("echo '`rm -rf /`'")
    assert review.decision != "block"
    assert "root_delete" not in review.as_dict()["matched_rules"]


def test_command_text_inside_quotes_does_not_trigger_rm_rules():
    review = check_command('echo "rm -rf /"')
    assert review.decision != "block"
    assert "root_delete" not in review.as_dict()["matched_rules"]
    assert "recursive_delete" not in review.as_dict()["matched_rules"]


def test_sensitive_redirection_warns_high():
    review = check_command("cat README.md > /etc/hosts")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "sensitive_redirection" in review.as_dict()["matched_rules"]
    assert "sensitive_file_write" in review.as_dict()["risk_categories"]


def test_malformed_shell_input_asks_for_clarification():
    review = check_command("echo 'unterminated")
    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert "shell_parse_error" in review.as_dict()["matched_rules"]
