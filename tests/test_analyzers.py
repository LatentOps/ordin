from commandgraph.analyzers import analyze_tokens, supported_analyzers
from commandgraph.shell import shell_tokens


def analyze(command: str):
    result = analyze_tokens(shell_tokens(command))
    assert result is not None
    return result


def effects(command: str) -> set[str]:
    return {item.effect for item in analyze(command).evidence}


def test_registry_covers_initial_high_value_families():
    supported = set(supported_analyzers())
    assert {
        "rm",
        "chmod",
        "chown",
        "git",
        "curl",
        "wget",
        "docker",
        "pip",
        "npm",
        "apt",
        "apt-get",
    } <= supported


def test_rm_analyzer_handles_wrappers_bundled_flags_and_targets():
    result = analyze("sudo rm -rf -- /tmp/build")
    assert result.command == "rm"
    assert result.targets == ("/tmp/build",)
    assert {
        "filesystem.delete",
        "filesystem.recursive_delete",
        "confirmation.bypass",
    } <= {item.effect for item in result.evidence}
    assert any(item.resource == "path:/tmp/build" for item in result.evidence)


def test_chmod_analyzer_tracks_mode_and_recursive_target():
    result = analyze("chmod --recursive 777 ./shared")
    assert result.targets == ("./shared",)
    assert "filesystem.permission_change" in effects("chmod --recursive 777 ./shared")
    assert "filesystem.recursive_permission_change" in effects(
        "chmod --recursive 777 ./shared"
    )
    assert any("broadly grants access" in note for note in result.notes)


def test_chown_analyzer_tracks_owner_and_target():
    result = analyze("chown -R user:group ./workspace")
    assert result.targets == ("./workspace",)
    assert "filesystem.ownership_change" in {
        item.effect for item in result.evidence
    }
    assert "filesystem.recursive_ownership_change" in {
        item.effect for item in result.evidence
    }


def test_git_analyzer_handles_global_options_before_subcommand():
    result = analyze("git -C /repo reset --hard HEAD~1")
    assert result.subcommand == "reset"
    assert "git.local_write" in {item.effect for item in result.evidence}
    assert "git.history_rewrite" in {item.effect for item in result.evidence}


def test_git_read_path_stays_read_only():
    result = analyze("git --no-pager status --short")
    assert {item.effect for item in result.evidence} == {"git.read"}


def test_git_force_push_emits_remote_write_and_history_rewrite():
    result = analyze("git push --force-with-lease origin main")
    assert {"git.remote_write", "git.history_rewrite"} <= {
        item.effect for item in result.evidence
    }


def test_curl_upload_and_file_output_are_distinguished():
    assert "network.upload" in effects(
        "curl --data-binary @payload.json https://example.com/api"
    )
    result = analyze("curl -o artifact.bin https://example.com/artifact.bin")
    names = {item.effect for item in result.evidence}
    assert {"network.connect", "network.download", "filesystem.write"} <= names
    assert any(item.resource == "path:artifact.bin" for item in result.evidence)


def test_wget_stdout_does_not_claim_filesystem_write():
    names = effects("wget -O - https://example.com/file")
    assert "network.download" in names
    assert "filesystem.write" not in names


def test_wget_default_download_writes_a_file():
    names = effects("wget https://example.com/file")
    assert {"network.download", "filesystem.write"} <= names


def test_docker_analyzer_handles_global_context_and_multiword_prune():
    result = analyze("docker --context prod system prune -af")
    assert result.subcommand == "system"
    assert "container.prune" in {item.effect for item in result.evidence}
    assert "confirmation.bypass" in {item.effect for item in result.evidence}


def test_docker_read_and_privileged_run_are_distinct():
    assert effects("docker ps") == {"container.read"}
    names = effects("docker run --privileged alpine true")
    assert {"container.create", "privilege.escalate"} <= names


def test_pip_analyzer_normalizes_python_module_invocation():
    result = analyze("python -m pip install requests")
    assert result.command == "pip"
    assert {"package.install", "code.execute"} <= {
        item.effect for item in result.evidence
    }


def test_pip_dry_run_does_not_emit_install_effect():
    names = effects("pip install --dry-run requests")
    assert "package.install" not in names
    assert "package.read" in names


def test_npm_ignore_scripts_suppresses_code_execution_effect():
    names = effects("npm install --ignore-scripts lodash")
    assert "package.install" in names
    assert "code.execute" not in names


def test_npm_run_is_code_execution():
    assert "code.execute" in effects("npm run build")


def test_apt_simulation_is_read_only():
    names = effects("apt-get -s install nginx")
    assert "package.install" not in names
    assert names == {"package.read"}


def test_apt_remove_yes_records_confirmation_bypass():
    names = effects("apt remove -y nginx")
    assert {"package.remove", "confirmation.bypass"} <= names
