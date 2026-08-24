from commandgraph.context import ExecutionContext
from commandgraph.review import review_command
from commandgraph.risk import check_command


def test_relative_recursive_delete_at_root_blocks_with_context():
    review = check_command(
        "rm -rf .",
        context=ExecutionContext(cwd="/"),
    )
    assert review.decision == "block"
    assert review.risk == "critical"
    assert "root_filesystem_mutation" in review.risk_categories


def test_filesystem_mutation_outside_repo_is_elevated():
    review = check_command(
        "chmod 600 secret.txt",
        context=ExecutionContext(cwd="/tmp", repo_root="/repo"),
    )
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "outside_repo_mutation" in review.risk_categories


def test_filesystem_mutation_inside_repo_keeps_base_risk():
    review = check_command(
        "chmod 600 secret.txt",
        context=ExecutionContext(cwd="/repo", repo_root="/repo"),
    )
    assert review.decision == "warn"
    assert review.risk == "medium"
    assert "outside_repo_mutation" not in review.risk_categories


def test_root_context_elevates_mutating_effects():
    review = check_command(
        "python -m pip install requests",
        context=ExecutionContext(euid=0),
    )
    assert review.decision == "warn"
    assert review.risk == "high"
    assert "elevated_context" in review.risk_categories


def test_root_context_does_not_elevate_read_only_effects():
    review = check_command(
        "git status --short",
        context=ExecutionContext(euid=0),
    )
    assert review.decision == "allow"
    assert review.risk == "low"
    assert "elevated_context" not in review.risk_categories


def test_command_review_serializes_supplied_context():
    context = ExecutionContext(cwd="/repo", shell="bash", agent="agent-test")
    review = review_command("git status", context=context)
    payload = review.as_dict()
    assert payload["context"]["cwd"] == "/repo"
    assert payload["context"]["agent"] == "agent-test"
