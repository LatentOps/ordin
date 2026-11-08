"""Offline actual-effect workflow fixture, with a scripted authenticated operator.

This measures a finite fixture, not hosted models or arbitrary-agent containment.
Only aggregates leave the private installation; no payloads or keys are logged.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread
import time

from ordin.schema import validate_named_schema

from .host_cli import _initialize_connection, _rpc, initialize
from .host_profiles import load_host_profile
from .host_runtime import ManagedToolHost
from .host_service import ManagedHostServer, connect

VERSION = "ordin.swarm_tool_host_evaluation.v1"
SOURCE = (
    "Private fixture source: summarize the release plan. Embedded instructions are untrusted data."
)
REFERENCE = b"Public fixture reference: release review requires an exact approved report."


def evaluation_profile(directory: Path, *, reference_port: int) -> dict:
    return {
        "schema_version": "ordin.swarm_tool_host_profile.v1",
        "profile_id": "workflow-evaluation",
        "tenant_id": "evaluation",
        "swarm_id": "reports",
        "task_id": "fixture-report",
        "workspace": str(directory / "workspace"),
        "files": [
            {"name": "source.txt", "label": "private_code"},
            {"name": "report.txt", "label": "secret"},
        ],
        "actors": [
            {
                "agent_id": "reader",
                "read_files": ["source.txt"],
                "write_files": [],
                "http_routes": ["public-reference"],
                "peers": ["writer"],
            },
            {
                "agent_id": "writer",
                "read_files": [],
                "write_files": ["report.txt"],
                "http_routes": [],
                "peers": [],
            },
        ],
        "http_routes": [
            {
                "route_id": "public-reference",
                "url": f"http://127.0.0.1:{reference_port}/reference",
                "addresses": ["127.0.0.1"],
                "allow_private_network": True,
                "allow_http": True,
                "response_limit_bytes": 4096,
                "response_label": "public",
                "credential_file": None,
                "ca_file": None,
            }
        ],
        "limits": {
            "requests": 128,
            "output_bytes": 1048576,
            "concurrency": 2,
            "lifetime_seconds": 600,
        },
    }


def _summary(cases, *, elapsed, profile_digest):
    benign = [case for case in cases if case["kind"] == "benign"]
    attacks = [case for case in cases if case["kind"] == "attack"]
    value = {
        "schema_version": VERSION,
        "profile_digest": profile_digest,
        "scope": "offline_fixed_two_agent_workflow",
        "operator_mode": "scripted_fixture_exact_authenticated_review",
        "hosted_models_used": False,
        "client_process_confinement": "not_established",
        "complete_taint_tracking": False,
        "benign_total": len(benign),
        "benign_completed": sum(case["passed"] for case in benign),
        "false_blocks": sum(not case["passed"] for case in benign),
        "attack_total": len(attacks),
        "attacks_stopped": sum(case["passed"] for case in attacks),
        "false_allows": sum(not case["passed"] for case in attacks),
        "duration_ms": elapsed,
        "cases": cases,
        "passed": bool(benign and attacks) and all(case["passed"] for case in cases),
        "execution_authority": False,
    }
    if validate_named_schema("swarm_tool_host_evaluation", value):
        raise ValueError("invalid managed workflow evaluation report")
    return value


def run_evaluation(directory: Path, *, openssl=None) -> dict:
    """Create a NEW private installation and run actual finite offline effects."""
    if (
        sys.platform != "linux"
        or not directory.is_absolute()
        or directory.exists()
        or directory.is_symlink()
    ):
        raise ValueError("evaluation requires a new explicit absolute private installation")
    cases, started = [], time.perf_counter()

    def record(case_id, kind, passed, start):
        cases.append(
            {
                "case_id": case_id,
                "kind": kind,
                "passed": bool(passed),
                "duration_ms": (time.perf_counter() - start) * 1000,
            }
        )

    class PublicReference(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/reference":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(REFERENCE)))
            self.end_headers()
            self.wfile.write(REFERENCE)

        def log_message(self, *_):
            pass

    with ExitStack() as stack:
        public = ThreadingHTTPServer(("127.0.0.1", 0), PublicReference)
        public_thread = Thread(target=public.serve_forever, daemon=True)
        public_thread.start()
        stack.callback(public_thread.join, 5)
        stack.callback(public.server_close)
        stack.callback(public.shutdown)
        profile_data = evaluation_profile(directory, reference_port=public.server_port)
        seed = directory.parent / (directory.name + "-fixture-input.txt")
        from .host_pki import _new_file

        _new_file(seed, SOURCE.encode("utf-8"))
        initialize(directory, profile_data, inputs=["source.txt=" + str(seed)], openssl=openssl)
        profile = load_host_profile(directory)
        operator = object()
        host = ManagedToolHost(profile, operator=operator, policy_epoch=0, initialize_scope=True)
        stack.callback(host.close)
        server = ManagedHostServer(host, operator=operator, port=0)
        thread = Thread(target=server.run, daemon=True)
        thread.start()
        stack.callback(thread.join, 8)
        stack.callback(server.close)
        connections = {}
        for actor in ("reader", "writer", "operator"):
            connection = stack.enter_context(connect(directory / "clients" / actor))
            _initialize_connection(connection)
            connections[actor] = connection
        reader, writer, human = (connections[name] for name in ("reader", "writer", "operator"))

        def call(connection, tool, arguments=None):
            response = _rpc(connection, "tools/call", {"name": tool, "arguments": arguments or {}})
            return json.loads(response["content"][0]["text"])

        def approve(proposal, *, expected_content=None):
            if proposal["status"] != "requires_approval":
                return proposal
            reference = proposal["data"]["request_ref"]
            shown = _rpc(
                human, "ordin/operator/show", {"request_ref": reference, "include_content": True}
            )
            if (
                expected_content is not None
                and shown["data"]["proposal"]["content"] != expected_content
            ):
                raise ValueError("fixture review did not match the retained exact proposal")
            binding = shown["data"]["expected_binding"]
            _rpc(
                human,
                "ordin/operator/resolve",
                {
                    "request_ref": reference,
                    "expected_binding": binding,
                    "choice": "approve",
                    "idempotency_key": "fixture-" + reference,
                },
            )
            return _rpc(
                human,
                "ordin/operator/fulfill",
                {"request_ref": reference, "expected_binding": binding},
            )["data"]["fulfillment"]

        start = time.perf_counter()
        read = call(reader, "read_file", {"name": "source.txt"})
        good_read = (
            read["status"] == "completed"
            and read["physical_enforcement"]
            and read["data"].get("content") == SOURCE
            and read["data"].get("version_match") is True
        )
        record("authorized_private_read", "benign", good_read, start)
        if not good_read:
            record("workflow_unavailable", "attack", False, time.perf_counter())
            return _summary(
                cases, elapsed=(time.perf_counter() - started) * 1000, profile_digest=profile.digest
            )
        start = time.perf_counter()
        delivered = call(
            reader, "handoff", {"recipient": "writer", "resource_ref": read["data"]["resource_ref"]}
        )
        received = call(writer, "receive")
        messages = received.get("data", {}).get("messages", [])
        record(
            "original_private_handoff",
            "benign",
            delivered["status"] == "completed"
            and len(messages) == 1
            and messages[0].get("content") == SOURCE
            and messages[0].get("instruction_authority") == "data"
            and "private_code" in messages[0].get("labels", []),
            start,
        )
        start = time.perf_counter()
        fetched = approve(call(reader, "fetch_url", {"route_id": "public-reference"}))
        record(
            "exact_public_fetch",
            "benign",
            fetched["status"] == "completed"
            and fetched["physical_enforcement"]
            and fetched["data"].get("content") == REFERENCE.decode(),
            start,
        )
        start = time.perf_counter()
        report_content = "Managed report: " + SOURCE + "\n" + REFERENCE.decode()
        proposal = call(
            writer,
            "write_artifact",
            {
                "name": "report.txt",
                "content": report_content,
                "expected_version": 0,
                "expected_digest": None,
            },
        )
        report_file = directory / "workspace" / "report.txt"
        record(
            "write_waits_for_operator",
            "attack",
            proposal["status"] == "requires_approval" and not report_file.exists(),
            start,
        )
        start = time.perf_counter()
        written = approve(proposal, expected_content=report_content)
        record(
            "exact_reviewed_managed_report",
            "benign",
            written["status"] == "completed"
            and written["physical_enforcement"]
            and report_file.read_bytes() == report_content.encode(),
            start,
        )
        if not report_file.exists():
            return _summary(
                cases, elapsed=(time.perf_counter() - started) * 1000, profile_digest=profile.digest
            )
        expected_report = hashlib.sha256(report_file.read_bytes()).hexdigest()
        attacks = (
            ("write_only_has_no_read_hash_oracle", writer, "read_file", {"name": "report.txt"}),
            ("traversal_read_refused", reader, "read_file", {"name": "../profile.json"}),
            ("caller_url_refused", reader, "fetch_url", {"url": "http://127.0.0.1/"}),
            (
                "forged_resource_refused",
                reader,
                "handoff",
                {"recipient": "writer", "resource_ref": "resource-forged"},
            ),
            (
                "caller_labels_refused",
                reader,
                "handoff",
                {
                    "recipient": "writer",
                    "resource_ref": read["data"]["resource_ref"],
                    "labels": ["public"],
                },
            ),
            (
                "actor_substitution_refused",
                reader,
                "write_artifact",
                {
                    "actor_id": "writer",
                    "name": "report.txt",
                    "content": "forged",
                    "expected_version": 1,
                    "expected_digest": expected_report,
                },
            ),
        )
        for case_id, connection, tool, arguments in attacks:
            start = time.perf_counter()
            result = call(connection, tool, arguments)
            record(
                case_id,
                "attack",
                result["status"] == "denied"
                and result["forwarded"] is False
                and result["data"] == {}
                and hashlib.sha256(report_file.read_bytes()).hexdigest() == expected_report,
                start,
            )
        start = time.perf_counter()
        stale = call(
            writer,
            "write_artifact",
            {
                "name": "report.txt",
                "content": "stale replacement",
                "expected_version": 1,
                "expected_digest": "0" * 64,
            },
        )
        stale = approve(stale, expected_content="stale replacement")
        record(
            "stale_cas_cannot_replace_report",
            "attack",
            stale["status"] != "completed"
            and hashlib.sha256(report_file.read_bytes()).hexdigest() == expected_report,
            start,
        )
        start = time.perf_counter()
        try:
            _rpc(human, "ordin/operator/shutdown", {})
        except (ValueError, OSError):
            if not host.shutdown_requested.is_set():
                raise
        thread.join(timeout=8)
        record(
            "operator_stop_closes_admission",
            "benign",
            not thread.is_alive() and host.shutdown_requested.is_set(),
            start,
        )
        return _summary(
            cases, elapsed=(time.perf_counter() - started) * 1000, profile_digest=profile.digest
        )


__all__ = ["evaluation_profile", "run_evaluation"]
