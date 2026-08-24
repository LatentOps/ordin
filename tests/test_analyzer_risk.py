from ordin.risk import check_command


def test_git_global_option_read_is_allowed():
    review = check_command("git -C /repo status --short")
    assert review.decision == "allow"
    assert review.risk == "low"
    assert "source_control_read" in review.risk_categories


def test_git_global_option_hard_reset_warns_high():
    review = check_command("git -C /repo reset --hard HEAD~1")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "history_rewrite" in review.risk_categories


def test_wget_is_classified_instead_of_unknown():
    review = check_command("wget https://example.com/file")
    assert review.decision == "warn"
    assert review.risk == "medium"
    assert "network_download" in review.risk_categories


def test_apt_simulation_is_allowed():
    review = check_command("apt-get -s install nginx")
    assert review.decision == "allow"
    assert review.risk == "low"
    assert review.risk_categories == ["package_metadata"]


def test_docker_global_context_prune_is_high_risk():
    review = check_command("docker --context prod system prune -af")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "container_cleanup" in review.risk_categories


def test_curl_upload_is_high_risk():
    review = check_command("curl --data-binary @payload.json https://example.com/api")
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "network_upload" in review.risk_categories


def test_existing_root_delete_block_still_wins():
    review = check_command("rm -rf /")
    assert review.decision == "block"
    assert review.risk == "critical"


def test_recognized_but_unknown_analyzer_invocation_asks():
    review = check_command("git totally-unknown-operation")
    assert review.decision == "ask"
    assert review.risk == "unknown"
    assert "unclassified_command" in review.risk_categories
