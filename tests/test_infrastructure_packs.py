import pytest

from ordin.analyzers import analyze_tokens
from ordin.data import data_health, find_command
from ordin.packs import discover_packs, enabled_packs
from ordin.risk import check_command
from ordin.search import search
from ordin.shell import shell_tokens


PRIORITY_PACKS = {
    "aws",
    "azure",
    "database",
    "gcloud",
    "github",
    "kubernetes",
    "remote",
    "systemd",
    "terraform",
}


def _effects(command: str) -> set[str]:
    analysis = analyze_tokens(shell_tokens(command))
    assert analysis is not None
    return {item.effect for item in analysis.evidence}


def _resources(command: str) -> set[str]:
    analysis = analyze_tokens(shell_tokens(command))
    assert analysis is not None
    return {item.resource for item in analysis.evidence if item.resource}


def test_priority_domain_packs_are_versioned_enabled_and_healthy():
    packs = {pack.name: pack for pack in discover_packs()}
    assert PRIORITY_PACKS <= set(packs)
    assert PRIORITY_PACKS <= {pack.name for pack in enabled_packs()}
    for name in PRIORITY_PACKS:
        assert packs[name].version == "1.0.0"
        assert packs[name].manifest["schema_version"] == "ordin.command_pack.v1"
        assert packs[name].effect_catalog_files == ("effects.json",)

    health = data_health()
    assert health["pack_errors"] == []
    assert health["resource_parity_errors"] == []
    assert health["graph_errors"] == []
    assert health["ok"] is True


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("inspect kubernetes pods", "kubectl"),
        ("preview terraform infrastructure changes", "terraform"),
        ("connect to a remote server with ssh", "ssh"),
        ("check systemd service status", "systemctl"),
        ("inspect github pull requests", "gh"),
        ("query postgresql database", "psql"),
        ("list aws resources", "aws"),
        ("list gcloud compute instances", "gcloud"),
        ("list azure resource groups", "az"),
    ],
)
def test_priority_domains_are_searchable(query, expected):
    assert expected in {result.command for result in search(query, limit=20)}


@pytest.mark.parametrize(
    ("command", "effect", "resource_prefix"),
    [
        ("kubectl delete deployment api -n prod", "infrastructure.delete", "kubernetes:"),
        ("terraform destroy -auto-approve", "infrastructure.delete", "terraform:"),
        ("tofu apply", "infrastructure.write", "terraform:"),
        ("ssh example-host uptime", "remote.execute", "remote:"),
        ("scp ./report.txt example-host:/tmp/report.txt", "network.upload", "remote:"),
        ("rsync example-host:/srv/data/ ./data/", "network.download", "remote:"),
        ("systemctl restart nginx", "service.control", "service:"),
        ("journalctl --vacuum-time=7d", "infrastructure.delete", "system-journal"),
        ("gh repo delete org/repo --yes", "infrastructure.delete", "github:"),
        ("psql -h db.example -d app -c 'DROP TABLE sessions'", "database.delete", "database:"),
        ("mysql -h db.example app -e 'UPDATE users SET active=0'", "database.write", "database:"),
        ("sqlite3 app.db 'SELECT count(*) FROM users'", "database.read", "database:"),
        ("redis-cli FLUSHALL", "database.delete", "database:"),
        ("aws ec2 terminate-instances --instance-ids i-123", "infrastructure.delete", "aws:"),
        (
            "gcloud compute instances delete web --zone us-central1-a",
            "infrastructure.delete",
            "gcloud:",
        ),
        ("az group delete --name prod --yes", "infrastructure.delete", "azure:"),
    ],
)
def test_domain_analyzers_emit_structured_effects_and_resources(command, effect, resource_prefix):
    assert effect in _effects(command)
    assert any(resource.startswith(resource_prefix) for resource in _resources(command))


@pytest.mark.parametrize(
    ("command", "effect"),
    [
        ("kubectl get secret api-token -o yaml", "secret.read"),
        ("terraform output -raw api_token", "secret.read"),
        ("gh auth token", "secret.read"),
        ("gh secret set DEPLOY_TOKEN", "secret.write"),
        ("psql -c 'GRANT ALL ON DATABASE app TO deployer'", "identity.permission_change"),
        ("aws secretsmanager get-secret-value --secret-id prod/api", "secret.read"),
        ("aws s3 cp ./backup.tar s3://bucket/backup.tar", "network.upload"),
        ("gcloud secrets versions access latest --secret api-key", "secret.read"),
        (
            "gcloud projects add-iam-policy-binding demo --member user:a@example.com",
            "identity.permission_change",
        ),
        (
            "az keyvault secret set --vault-name prod --name api-key --value REDACTED",
            "secret.write",
        ),
        (
            "az role assignment create --assignee user@example.com --role Reader",
            "identity.permission_change",
        ),
    ],
)
def test_sensitive_remote_operations_are_classified(command, effect):
    assert effect in _effects(command)


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete deployment api -n prod",
        "terraform destroy -auto-approve",
        "ssh example-host 'sudo systemctl restart nginx'",
        "rsync --delete ./data/ example-host:/srv/data/",
        "systemctl restart nginx",
        "journalctl --vacuum-size=1G",
        "gh repo delete org/repo --yes",
        "psql -c 'DROP DATABASE app'",
        "redis-cli FLUSHALL",
        "aws ec2 terminate-instances --instance-ids i-123",
        "gcloud compute instances delete web --zone us-central1-a",
        "az group delete --name prod --yes",
    ],
)
def test_destructive_or_remote_write_operations_never_silently_allow(command):
    review = check_command(command)
    assert review.decision in {"warn", "block"}
    assert review.risk in {"high", "critical"}


@pytest.mark.parametrize(
    "command",
    [
        "kubectl get pods",
        "terraform plan",
        "tofu show",
        "ssh example-host",
        "systemctl status nginx",
        "journalctl -n 20",
        "gh pr list",
        "psql -c 'SELECT 1'",
        "sqlite3 app.db 'SELECT 1'",
        "aws s3 ls",
        "gcloud compute instances list",
        "az group list",
    ],
)
def test_read_only_domain_operations_are_low_risk(command):
    review = check_command(command)
    assert review.decision == "allow"
    assert review.risk == "low"


def test_exact_pack_selection_removes_other_domain_semantics(monkeypatch):
    monkeypatch.setenv("ORDIN_PACKS", "kubernetes")

    assert [pack.name for pack in enabled_packs()] == ["kubernetes"]
    assert find_command("kubectl") is not None
    assert find_command("aws") is None
    assert analyze_tokens(shell_tokens("kubectl get pods")) is not None
    assert analyze_tokens(shell_tokens("aws s3 ls")) is None

    unknown = check_command("aws s3 ls")
    assert unknown.decision == "ask"
    assert unknown.risk == "unknown"


def test_disabling_all_packs_removes_new_domain_analyzers(monkeypatch):
    monkeypatch.setenv("ORDIN_PACKS", "")
    for executable in (
        "aws",
        "az",
        "gcloud",
        "gh",
        "kubectl",
        "psql",
        "ssh",
        "systemctl",
        "terraform",
        "tofu",
    ):
        assert find_command(executable) is None
        assert analyze_tokens(shell_tokens(f"{executable} --help")) is None
