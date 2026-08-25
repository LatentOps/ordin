from ordin.risk import check_command


def test_read_only_git_subcommand_uses_semantic_low_risk():
    review = check_command("git status --short")
    assert review.decision == "allow"
    assert review.risk == "low"
    assert "source_control_read" in review.risk_categories


def test_git_hard_reset_is_elevated_by_semantic_effect():
    review = check_command("git reset --hard HEAD~1")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "history_rewrite" in review.risk_categories
    assert "force_push" not in review.matched_rules


def test_find_delete_is_elevated_without_a_regex_rule():
    review = check_command("find . -name '*.tmp' -delete")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "filesystem_delete" in review.risk_categories


def test_curl_upload_is_elevated_by_flag_effect():
    review = check_command("curl --upload-file payload.txt https://example.com/upload")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "network_upload" in review.risk_categories


def test_docker_read_and_delete_subcommands_differ():
    read_review = check_command("docker ps")
    delete_review = check_command("docker rm app")

    assert read_review.decision == "allow"
    assert read_review.risk == "low"
    assert "container_read" in read_review.risk_categories

    assert delete_review.decision == "warn"
    assert delete_review.risk == "high"
    assert "container_delete" in delete_review.risk_categories


def test_pip_read_and_install_subcommands_differ():
    read_review = check_command("python -m pip list")
    install_review = check_command("python -m pip install requests")

    assert read_review.decision == "allow"
    assert read_review.risk == "low"
    assert "package_metadata" in read_review.risk_categories

    assert install_review.decision == "warn"
    assert install_review.risk == "medium"
    assert "package_install" in install_review.risk_categories


def test_existing_regex_rules_still_override_semantic_baseline():
    review = check_command("rm -rf /")
    assert review.decision == "block"
    assert review.risk == "critical"
    assert "root_filesystem_mutation" in review.risk_categories
