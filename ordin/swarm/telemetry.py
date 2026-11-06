"""Explicit local exports of redacted diagnostic data, never trusted host evidence."""

from __future__ import annotations

from typing import Any

from ordin import __version__
from ordin._runtime_json import digest
from .audit import verify_swarm_audit


def _events(bundle, maximum):
    if type(maximum) is not int or not 1 <= maximum <= 4096 or not verify_swarm_audit(bundle).valid:
        raise ValueError("bounded valid redacted audit bundle required")
    return bundle["events"][-maximum:]


def export_swarm_ocsf(
    bundle: dict[str, Any], *, maximum_events: int = 256
) -> tuple[dict[str, Any], ...]:
    """OCSF 1.8 Detection Finding compatibility; source remains diagnostic data."""
    result = []
    for event in _events(bundle, maximum_events):
        if (
            event["state"] not in {"denied", "unknown", "paused", "revoked", "quarantined"}
            and event["kind"] != "risk_signal"
        ):
            continue
        severity = {"unknown": 0, "low": 2, "medium": 3, "high": 4, "critical": 5}.get(
            event["facts"].get("risk", event["facts"].get("model_risk", "unknown")), 0
        )
        reference = digest(event)
        result.append(
            {
                "category_uid": 2,
                "class_uid": 2004,
                "activity_id": 1,
                "type_uid": 200401,
                "severity_id": severity,
                "time": min(int(event["admitted_at"] * 1000), 2**53 - 1),
                "status_id": 1,
                "is_alert": True,
                "message": "Ordin swarm diagnostic finding",
                "metadata": {
                    "version": "1.8.0",
                    "uid": reference,
                    "product": {
                        "name": "Ordin",
                        "vendor_name": "LatentOps",
                        "version": __version__,
                    },
                    "profiles": ["security_control"],
                    "event_code": "swarm_" + event["kind"],
                    "original_event_uid": event["event_hash"],
                },
                "finding_info": {
                    "uid": reference,
                    "title": "Ordin swarm diagnostic finding",
                    "types": [event["kind"]],
                    "created_time": min(int(event["admitted_at"] * 1000), 2**53 - 1),
                },
                "unmapped": {
                    "ordin": {
                        "tenant_ref": bundle["tenant_ref"],
                        "scope_ref": bundle["scope_ref"],
                        "evidence": event["evidence"],
                        "state": event["state"],
                        "refs": event["refs"],
                        "diagnostic_only": True,
                        "execution_authority": False,
                    }
                },
            }
        )
    return tuple(result)


def export_swarm_spans(bundle: dict[str, Any], exporter, *, maximum_spans: int = 256) -> int:
    """Use an explicit SDK exporter. No global provider or auto network exporter."""
    events = _events(bundle, maximum_spans)
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider, SpanLimits
        from opentelemetry.sdk.trace.export import (
            SimpleSpanProcessor,
            SpanExporter,
            SpanExportResult,
        )
        from opentelemetry.sdk.trace.sampling import ALWAYS_ON
        from opentelemetry.metrics import NoOpMeterProvider
    except ImportError:
        raise ValueError("optional OpenTelemetry SDK is not installed") from None
    if not isinstance(exporter, SpanExporter):
        raise ValueError("explicit original OpenTelemetry SpanExporter required")

    class CheckedExporter(SpanExporter):
        failed = False

        def export(self, spans):
            try:
                result = exporter.export(spans)
                if result is not SpanExportResult.SUCCESS:
                    self.failed = True
                return result
            except Exception:
                self.failed = True
                return SpanExportResult.FAILURE

        def shutdown(self):
            exporter.shutdown()

    checked = CheckedExporter()
    provider = TracerProvider(
        resource=Resource(
            {"service.name": "ordin-local-swarm", "ordin.privacy": "tenant_keyed_hmac_metadata"}
        ),
        sampler=ALWAYS_ON,
        shutdown_on_exit=False,
        span_limits=SpanLimits(
            max_attributes=32, max_attribute_length=128, max_events=0, max_links=0
        ),
    )
    provider.add_span_processor(SimpleSpanProcessor(checked, meter_provider=NoOpMeterProvider()))
    tracer = provider.get_tracer("ordin.swarm.diagnostics", __version__)
    try:
        for event in events:
            start = int(event["admitted_at"] * 1_000_000_000)
            supported_time = 0 <= start <= 2**63 - 1
            if not supported_time:
                start = 0
            attributes = {
                "ordin.tenant.ref": bundle["tenant_ref"],
                "ordin.evidence": event["evidence"],
                "ordin.state": event["state"],
                "ordin.execution_authority": False,
                "ordin.diagnostic_only": True,
                "ordin.time_supported": supported_time,
                "ordin.capture_instant": True,
                **{"ordin." + name + ".ref": value for name, value in event["refs"].items()},
            }
            span = tracer.start_span(
                "ordin.swarm." + event["kind"], start_time=start, attributes=attributes
            )
            span.end(end_time=start)
        if not provider.force_flush(timeout_millis=1000):
            checked.failed = True
    finally:
        provider.shutdown()
    if checked.failed:
        raise ValueError("explicit telemetry exporter did not confirm export")
    return len(events)


def export_swarm_span_json(bundle: dict[str, Any], *, maximum_spans: int = 256) -> dict[str, Any]:
    """Bounded local JSON captured through the optional real SDK, without a network sink."""
    try:
        from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    except ImportError:
        raise ValueError("optional OpenTelemetry SDK is not installed") from None

    class LocalExporter(SpanExporter):
        def __init__(self):
            self.spans = []

        def export(self, spans):
            for span in spans:
                self.spans.append(
                    {
                        "name": span.name,
                        "trace_id": format(span.context.trace_id, "032x"),
                        "span_id": format(span.context.span_id, "016x"),
                        "start_time_unix_nano": span.start_time,
                        "end_time_unix_nano": span.end_time,
                        "attributes": dict(span.attributes),
                        "resource": dict(span.resource.attributes),
                    }
                )
            return SpanExportResult.SUCCESS

    exporter = LocalExporter()
    export_swarm_spans(bundle, exporter, maximum_spans=maximum_spans)
    return {
        "schema_version": "ordin.swarm_otel_export.v1",
        "spans": exporter.spans,
        "diagnostic_only": True,
        "execution_authority": False,
    }
