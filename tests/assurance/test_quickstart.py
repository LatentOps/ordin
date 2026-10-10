"""Packaged synthetic quickstart runs with external creation rejected."""

import json

from ordin.assurance.quickstart import run_quickstart


def test_owned_quickstart_protects_and_explains_without_execution(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("quickstart attempted external execution")

    monkeypatch.setattr("subprocess.Popen", refuse)
    monkeypatch.setattr("socket.create_connection", refuse)
    result = run_quickstart()
    assert (
        result["synthetic_only"]
        and not result["actions_executed"]
        and not result["model_or_scanner_called"]
    )
    assert result["profile_content"]["approved"] is False
    assert result["protected_profile_demo"]["safe_disposition"] == "execute"
    assert result["protected_profile_demo"]["network_disposition"] == "deny"
    assert (
        result["simulation"]["authority_delta"] == "narrowed"
        and not result["simulation"]["critical_misses"]
    )
    assert result["challenge"]["failures"] and all(
        status == "verified_failure" for status in result["challenge"]["replayed"]
    )
    assert result["offline_finding_import"]["finding_count"] == 1
    assert result["offline_finding_import"]["finding_confirmation"] == "not_performed"
    assert (
        not result["attack_path"]["runtime_observations"]
        and not result["delegation"]["grant_issued"]
    )
    assert result["external_claims"]["closure"] == "not_performed"
    assert "curl https" not in json.dumps(result)
