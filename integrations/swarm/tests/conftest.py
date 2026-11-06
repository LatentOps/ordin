"""Conformance never uses hosted models, telemetry or runtime network access."""

import socket
import pytest


@pytest.fixture(autouse=True)
def no_runtime_network(monkeypatch):
    for name, value in {
        "CREWAI_TELEMETRY_DISABLED": "true",
        "OTEL_SDK_DISABLED": "true",
        "ANONYMIZED_TELEMETRY": "false",
        "LANGSMITH_TRACING": "false",
        "LANGCHAIN_TRACING_V2": "false",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "DO_NOT_TRACK": "1",
        "AUTOGEN_DISABLE_RUNTIME_TRACING": "true",
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "LANGSMITH_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def denied(*args, **kwargs):
        raise AssertionError("conformance attempted a runtime network connection")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
