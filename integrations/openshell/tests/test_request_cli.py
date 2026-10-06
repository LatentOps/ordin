import json

from ordin_openshell.cli import main
from test_requests import graphql_contract, request_boundary


def test_request_artifact_cli_derives_compiles_validates_and_verifies(tmp_path, capsys):
    review, request = graphql_contract()
    review_file = tmp_path / "review.json"
    review_file.write_text(json.dumps(review.as_dict()))
    request_file = tmp_path / "request.json"
    request_file.write_text(json.dumps(request.as_dict()))
    boundary_file = tmp_path / "boundary.json"
    boundary_file.write_text(json.dumps(request_boundary(request).as_dict()))
    output = tmp_path / "policy.json"
    assert main(["derive-requests", "--review", str(review_file)]) == 0
    assert json.loads(capsys.readouterr().out)["request_contract_id"] == request.request_contract_id
    assert (
        main(
            [
                "compile-requests",
                "--request-contract",
                str(request_file),
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "success"
    assert main(["validate", "--policy", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "success"
    assert (
        main(
            [
                "verify-requests",
                "--request-contract",
                str(request_file),
                "--request-boundary",
                str(boundary_file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["coverage"]["requests"] is True


def test_optional_ocsf_cli_exports_private_free_review_and_correlation_findings(tmp_path, capsys):
    from ordin import Ordin, ActionEnvelope

    review = Ordin().review_action(ActionEnvelope.shell("rm -rf /", action_id="private-id"))
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review.as_dict()))
    failed = tmp_path / "correlation.json"
    failed.write_text(json.dumps({"status": "rejected", "raw": "PRIVATE-TOKEN"}))
    assert (
        main(
            [
                "export-ocsf",
                "--review",
                str(path),
                "--correlation-result",
                str(failed),
                "--time-ms",
                "1",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "PRIVATE-TOKEN" not in output and "private-id" not in output and "rm -rf" not in output
    events = json.loads(output)["events"]
    assert len(events) == 2 and all(e["class_uid"] == 2004 for e in events)
