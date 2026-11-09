"""Real optional SDK spans and legacy trace imports stay diagnostic and redacted."""

import json
import sqlite3
from contextlib import closing

import pytest

from ordin import ActionEnvelope, Ordin
from ordin.audit import JsonlAuditSink, audit_tail_checkpoint, verify_audit_checkpoint
from ordin.trace_capture import TraceRecorder, trace_tail_checkpoint, verify_trace_checkpoint
from ordin.swarm.telemetry import export_swarm_ocsf, export_swarm_spans, export_swarm_span_json
from tests.test_swarm_operator import operator_fixture


def test_legacy_audit_and_trace_anchors_detect_edits_but_do_not_make_observations_trusted(tmp_path):
    with operator_fixture(tmp_path) as (data, source, *_):
        review = Ordin().review_action(
            ActionEnvelope.shell("printf SYNTHETIC_PRIVATE_PAYLOAD", action_id="private-case")
        )
        sink = JsonlAuditSink(tmp_path / "legacy.jsonl", hash_chain=True)
        sink.record(review)
        anchor = audit_tail_checkpoint(sink.path)
        assert verify_audit_checkpoint(sink.path, anchor)
        recorder = TraceRecorder(
            tmp_path / "trace.db",
            integration="python",
            session_id="private-session",
            raw_local=True,
        )
        recorder.record_review(review)
        trace_anchor = trace_tail_checkpoint(recorder.path)
        assert verify_trace_checkpoint(recorder.path, trace_anchor)
        source.import_audit(sink.path, operator=data["operator"])
        source.import_trace(recorder.path, operator=data["operator"])
        assert source.flush(operator=data["operator"])
        bundle = source.journal.export(operator=data["operator"])
        assert all(row["evidence"] == "diagnostic" for row in bundle["events"])
        assert "SYNTHETIC_PRIVATE_PAYLOAD" not in json.dumps(bundle)
        with closing(sqlite3.connect(recorder.path)) as connection, connection:
            connection.execute("DELETE FROM events")
        assert not verify_trace_checkpoint(recorder.path, trace_anchor)
        sink.record(Ordin().review_action(ActionEnvelope.shell("pwd", action_id="different")))
        assert not verify_audit_checkpoint(sink.path, anchor)


def test_ocsf_uses_only_redacted_ids_and_explicit_diagnostic_evidence(tmp_path):
    with operator_fixture(tmp_path) as (data, source, *_):
        source.record_risk(
            severity="high",
            confidence=0.75,
            model_ref="SYNTHETIC_PRIVATE_MODEL",
            action_ref="SYNTHETIC_PRIVATE_ACTION",
            operator=data["operator"],
        )
        assert source.flush(operator=data["operator"])
        exported = export_swarm_ocsf(source.journal.export(operator=data["operator"]))
        assert len(exported) == 1 and exported[0]["class_uid"] == 2004
        assert exported[0]["unmapped"]["ordin"]["evidence"] == "diagnostic"
        assert not exported[0]["unmapped"]["ordin"]["execution_authority"]
        assert "SYNTHETIC_PRIVATE" not in json.dumps(exported)


def test_actual_opentelemetry_sdk_does_not_add_environment_resources_or_raw_ids(
    tmp_path, monkeypatch
):
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "secret=SYNTHETIC_ENV_SECRET")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "SYNTHETIC_ENV_SERVICE")
    with operator_fixture(tmp_path) as (data, source, *_):
        source.record_risk(
            severity="medium",
            confidence=0.5,
            model_ref="SYNTHETIC_PRIVATE_MODEL",
            action_ref="SYNTHETIC_PRIVATE_ACTION",
            operator=data["operator"],
        )
        assert source.flush(operator=data["operator"])
        exporter = InMemorySpanExporter()
        assert export_swarm_spans(source.journal.export(operator=data["operator"]), exporter) == 1
        spans = exporter.get_finished_spans()
        assert len(spans) == 1 and spans[0].attributes["ordin.evidence"] == "diagnostic"
        assert not spans[0].attributes["ordin.execution_authority"]
        assert spans[0].end_time == spans[0].start_time
        raw = str(spans[0].attributes) + str(spans[0].resource.attributes)
        assert "SYNTHETIC_" not in raw and "process.pid" not in raw
        local = export_swarm_span_json(source.journal.export(operator=data["operator"]))
        assert local["schema_version"] == "ordin.swarm_otel_export.v1"
        assert local["spans"][0]["attributes"]["ordin.task.ref"].startswith("hmac:")
        assert "SYNTHETIC_" not in json.dumps(local)


@pytest.mark.parametrize("format", ("audit", "ocsf", "otel"))
def test_local_cli_export_formats_are_explicit_bounded_and_private(tmp_path, capsys, format):
    from ordin.swarm.cli import main

    if format == "otel":
        pytest.importorskip("opentelemetry.sdk")
    with operator_fixture(tmp_path) as (data, source, *_):
        source.record_risk(
            severity="high",
            confidence=0.75,
            model_ref="PRIVATE_MODEL",
            action_ref="PRIVATE_ACTION",
            operator=data["operator"],
        )
        assert source.flush(operator=data["operator"], timeout=5)
        report = tmp_path / "audit.json"
        report.write_text(json.dumps(source.journal.export(operator=data["operator"])))
        output = tmp_path / "export.json"
        assert (
            main(
                [
                    "export",
                    "--report",
                    str(report),
                    "--format",
                    format,
                    "--output",
                    str(output),
                    "--json",
                ]
            )
            == 0
        )
        result = json.loads(capsys.readouterr().out)
        assert not result["execution_authority"]
        from ordin.schema import validate_named_schema

        assert not validate_named_schema(
            {
                "audit": "swarm_audit_bundle",
                "ocsf": "swarm_ocsf_export",
                "otel": "swarm_otel_export",
            }[format],
            result,
        )
        assert "PRIVATE_" not in output.read_text()
        assert main(["status", "--format", format, "--json"]) == (0 if format == "audit" else 2)
        capsys.readouterr()


def test_explicit_telemetry_exporter_failure_is_not_reported_as_delivery(tmp_path):
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class FailingExporter(SpanExporter):
        def export(self, spans):
            return SpanExportResult.FAILURE

    with operator_fixture(tmp_path) as (data, source, *_):
        source.record_risk(
            severity="high",
            confidence=1,
            model_ref="model",
            action_ref="action",
            operator=data["operator"],
        )
        assert source.flush(operator=data["operator"], timeout=5)
        with pytest.raises(ValueError, match="did not confirm"):
            export_swarm_spans(source.journal.export(operator=data["operator"]), FailingExporter())
