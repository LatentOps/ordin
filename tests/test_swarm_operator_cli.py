"""Offline reports remain unverified; live CLI uses the real TLS operator API."""

from concurrent.futures import ThreadPoolExecutor
import json
import socket

from ordin.schema import validate_named_schema
from ordin.swarm.cli import main
from tests.swarm_operator_contract_samples import operator_contract_samples
from tests.test_swarm_operator import operator_fixture
from tests.test_swarm_delegation import CERTS


def test_unconfigured_queries_start_no_service_and_claim_no_coverage(capsys):
    for command in ("list", "status", "graph", "incidents", "policy", "coverage"):
        assert main([command, "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert not validate_named_schema("swarm_operator_unconfigured", result)


def test_offline_snapshot_cannot_authenticate_controls_and_dashboard_is_local(tmp_path, capsys):
    snapshot = operator_contract_samples()["swarm_operator_snapshot"]
    snapshot["verified_live_source"], snapshot["coordinator_online"] = True, True
    path, dashboard = tmp_path / "report.json", tmp_path / "dashboard.html"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    assert main(["status", "--report", str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert not result["verified_live_source"] and not result["coordinator_online"]
    assert not validate_named_schema("swarm_operator_snapshot", result)
    assert main(["pause", "--report", str(path), "--json"]) == 2
    assert "operator.request_refused" in capsys.readouterr().out
    assert main(["dashboard", "--report", str(path), "--output", str(dashboard), "--json"]) == 0
    capsys.readouterr()
    html = dashboard.read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html and "<script" not in html and "fetch(" not in html
    assert "data:application/json;base64," in html


def test_audit_cli_detects_truncation_against_external_checkpoint(tmp_path, capsys):
    samples = operator_contract_samples()
    bundle, checkpoint = samples["swarm_audit_bundle"], samples["swarm_audit_checkpoint"]
    file, anchor = tmp_path / "audit.json", tmp_path / "checkpoint.json"
    file.write_text(json.dumps(bundle), encoding="utf-8")
    anchor.write_text(json.dumps(checkpoint), encoding="utf-8")
    assert (
        main(["audit", "verify", "--report", str(file), "--checkpoint", str(anchor), "--json"]) == 0
    )
    capsys.readouterr()
    bundle.update(events=[], tail_sequence=0, tail_hash="0" * 64)
    file.write_text(json.dumps(bundle), encoding="utf-8")
    assert (
        main(["audit", "verify", "--report", str(file), "--checkpoint", str(anchor), "--json"]) == 2
    )
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_live_cli_uses_actual_hostname_verified_mutual_tls(tmp_path, capsys):
    with operator_fixture(tmp_path) as (_, _, _, directory, _, api, *_):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)

            def serve():
                connection, _ = listener.accept()
                with directory.authenticator._tls.wrap_socket(
                    connection, server_side=True
                ) as protected:
                    api.serve_one(protected)

            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(serve)
                assert (
                    main(
                        [
                            "status",
                            "--host",
                            "localhost",
                            "--port",
                            str(listener.getsockname()[1]),
                            "--ca",
                            str(CERTS / "ca.pem"),
                            "--cert",
                            str(CERTS / "broker-a.pem"),
                            "--key",
                            str(CERTS / "broker-a-key.pem"),
                            "--json",
                        ]
                    )
                    == 0
                )
                pending.result(timeout=10)
        result = json.loads(capsys.readouterr().out)
        assert result["verified_live_source"] and not result["execution_authority"]
