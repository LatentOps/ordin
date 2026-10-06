"""Explicit caller-owned probes for an existing non-secret OpenShell test sandbox.

This is a validation/example program, separate from execution-free Ordin review.
It never creates/starts/retries sandboxes or changes their policy. Configure the
exact GET policy and a POSIX-writable read-only fixture before invoking it.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "integrations/openshell")]
from ordin import (
    ActionEnvelope,
    ActionReview,
    AgentGate,
    IntegrationSession,
    Ordin,
    SessionIdentity,
)
from ordin._runtime_json import digest, thaw
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_requirements import RuntimeRequirementProfile
from ordin_openshell.apply import read_runtime_policy
from ordin_openshell.backend_cli import OpenShellCLI, identifier
from ordin_openshell.correlation import CorrelationBinding, CorrelationStore
from ordin_openshell.observations import ingest_openshell_event, parse_openshell_event
from ordin_openshell.model import PUBLIC_IPV4_RANGES


def validate_demo_fixtures(policy, filesystem_policy):
    policy = thaw(policy)
    rules = tuple(policy["network_policies"].values())
    if not rules or any(
        rule["binaries"] != [{"path": "/usr/bin/curl"}]
        or len(rule["endpoints"]) != 1
        or rule["endpoints"][0]
        != {
            "host": "api.github.com",
            "port": 443,
            "protocol": "rest",
            "enforcement": "enforce",
            "allowed_ips": list(PUBLIC_IPV4_RANGES),
            "rules": [{"allow": {"method": "GET", "path": "/repos/LatentOps/ordin/issues/37"}}],
        }
        for rule in rules
    ):
        raise ValueError("demo_requires_exact_read_only_network_fixture")
    protected = "/readonly/input.txt"
    if not any(
        protected == p or protected.startswith(p.rstrip("/") + "/")
        for p in filesystem_policy["read_only"]
    ) or any(
        protected == p or protected.startswith(p.rstrip("/") + "/")
        for p in filesystem_policy["read_write"]
    ):
        raise ValueError("demo_requires_read_only_filesystem_fixture")


def probe_identity(metadata):
    if metadata.get("host") == "example.com" and metadata.get("port") == 443:
        return "unrelated_host"
    if (
        metadata.get("host") != "api.github.com"
        or metadata.get("port") != 443
        or metadata.get("path") != "/repos/LatentOps/ordin/issues/37"
    ):
        return None
    return {"GET": "get", "POST": "post"}.get(metadata.get("method"))


def run(args):
    identifier(args.sandbox)
    identifier(args.filesystem_sandbox)
    cli = OpenShellCLI(
        args.openshell, workspace=args.workspace, gateway_endpoint=args.gateway_endpoint
    )
    snapshot = read_runtime_policy(cli, args.sandbox)
    fs_snapshot = read_runtime_policy(cli, args.filesystem_sandbox)
    validate_demo_fixtures(snapshot.policy, fs_snapshot.policy["filesystem_policy"])
    profile_filesystem = tuple(
        FilesystemCapability(access, path, "prefix")
        for path in snapshot.policy["filesystem_policy"]["read_only"]
        for access in ("read", "execute")
    )
    profile_filesystem += tuple(
        FilesystemCapability(access, path, "prefix")
        for path in snapshot.policy["filesystem_policy"]["read_write"]
        for access in ("read", "write", "delete", "execute")
    )
    profile = RuntimeRequirementProfile(
        "demo-observed-startup-policy",
        profile_filesystem,
        {"curl": "/usr/bin/curl", "cat": "/usr/bin/cat"},
        True,
    )
    session = IntegrationSession(
        SessionIdentity("openshell-demo", args.sandbox),
        AgentGate(Ordin(runtime_requirements=profile)),
    )
    from ordin.runtime_observation import RuntimeEvidenceSource

    source = RuntimeEvidenceSource(
        "openshell", session.runtime_session_digest, snapshot.sandbox_id, snapshot.policy_digest
    )
    session.bind_runtime_source(source)
    # Review the exact program/argv used by the caller. Probe diagnostics are
    # captured by the host, not added as curl flags after review.
    url = "https://api.github.com/repos/LatentOps/ordin/issues/37"
    actions = (
        (
            "get",
            [
                "/usr/bin/curl",
                "--disable",
                "--silent",
                "--show-error",
                "--fail",
                "--request",
                "GET",
                url,
            ],
        ),
        (
            "post",
            ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--request", "POST", url],
        ),
        (
            "unrelated_host",
            ["/usr/bin/curl", "--disable", "--silent", "--show-error", "https://example.com/"],
        ),
    )
    records = []
    prefix = [
        args.openshell,
        "--gateway-endpoint",
        args.gateway_endpoint,
        "--workspace",
        args.workspace,
    ]
    observed_before = int(time.time() * 1000)
    for name, program in actions:
        action = ActionEnvelope.shell(shlex.join(program), action_id="demo-" + name)
        decision = session.evaluate(action)
        assert action.action_id is not None
        # Negative probes are deliberate host test requests. They do not make
        # Ordin execute, automatically retry, or broaden an agent's permission.
        response = subprocess.run(
            prefix
            + [
                "sandbox",
                "exec",
                "--name",
                args.sandbox,
                "--no-tty",
                "--no-login-shell",
                "--timeout",
                "30",
                "--",
                *program,
            ],
            capture_output=True,
            text=True,
            timeout=40,
            stdin=subprocess.DEVNULL,
        )
        data = None
        try:
            data = json.loads(response.stdout)
        except ValueError:
            pass
        expected = (
            name == "get"
            and response.returncode == 0
            and isinstance(data, dict)
            and data.get("number") == 37
            or name == "post"
            and isinstance(data, dict)
            and data.get("error") == "policy_denied"
            or name == "unrelated_host"
            and response.returncode != 0
        )
        records.append(
            {
                "name": name,
                "passed": bool(expected),
                "caller_exit": response.returncode,
                "ordin_decision": decision.review.decision,
                "action_digest": session.runtime_contract(action.action_id).action_digest,
                "contract_id": session.runtime_contract(action.action_id).contract_id,
                "policy_denied": bool(data and data.get("error") == "policy_denied"),
            }
        )
    fs_code = """import json,os,stat
p='/readonly/input.txt'; s=os.stat(p)
r={'euid':os.geteuid(),'file_uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'read_succeeded':bool(open(p).read())}
open('/tmp/allowed-control.txt','w').write('non-secret control'); r['write_control_succeeded']=True
try:
 open(p,'w').write('must be denied'); r['protected_write_denied']=False
except PermissionError:
 r['protected_write_denied']=True
print(json.dumps(r))
"""
    fs_session = IntegrationSession(
        SessionIdentity("openshell-demo", args.filesystem_sandbox), AgentGate(Ordin())
    )
    fs_source = RuntimeEvidenceSource(
        "openshell",
        fs_session.runtime_session_digest,
        fs_snapshot.sandbox_id,
        fs_snapshot.policy_digest,
    )
    fs_session.bind_runtime_source(fs_source)
    read_program = ["/usr/bin/cat", "/readonly/input.txt"]
    fs_session.evaluate(ActionEnvelope.shell(shlex.join(read_program), action_id="fs-read"))
    fs_read = subprocess.run(
        prefix
        + [
            "sandbox",
            "exec",
            "--name",
            args.filesystem_sandbox,
            "--no-tty",
            "--no-login-shell",
            "--timeout",
            "30",
            "--",
            *read_program,
        ],
        capture_output=True,
        text=True,
        timeout=40,
        stdin=subprocess.DEVNULL,
    )
    probe_program = ["/usr/bin/python3", "-c", fs_code]
    fs_session.evaluate(
        ActionEnvelope.shell(shlex.join(probe_program), action_id="fs-negative-probe")
    )
    probe_contract = fs_session.runtime_contract("fs-negative-probe")
    response = subprocess.run(
        prefix
        + [
            "sandbox",
            "exec",
            "--name",
            args.filesystem_sandbox,
            "--no-tty",
            "--no-login-shell",
            "--timeout",
            "30",
            "--",
            *probe_program,
        ],
        capture_output=True,
        text=True,
        timeout=40,
        stdin=subprocess.DEVNULL,
    )
    fs = json.loads(response.stdout) if response.returncode == 0 else {}
    fs_passed = (
        fs_read.returncode == 0
        and bool(fs_read.stdout)
        and fs.get("euid") == fs.get("file_uid") == 1000
        and fs.get("mode", 0) & 0o222 != 0
        and fs.get("read_succeeded")
        and fs.get("write_control_succeeded")
        and fs.get("protected_write_denied")
    )
    records.append({"name": "filesystem_positive_controls", "passed": bool(fs_passed), **fs})
    if fs_passed:
        # This reports a trusted host-controlled probe result, not a native
        # filesystem OCSF enforcement event (absent in the pinned backend).
        from ordin import ObservedResource

        observation = fs_source.observe(
            probe_contract,
            observation_id="host-fs-probe",
            trust="backend_observed",
            enforcement_point="filesystem",
            outcome="denied",
            operation="filesystem.write",
            effects=("filesystem.write",),
            resources=(ObservedResource("path", "/readonly/input.txt"),),
            reason_code="readonly_probe_denied",
        )
        fs_session.observe_runtime(observation)
        later = fs_session.evaluate(ActionEnvelope.shell("git status --short", action_id="later"))
        assert isinstance(later.review, ActionReview) and later.review.provenance is not None
        records.append(
            {
                "name": "filesystem_evidence_return",
                "passed": any(
                    r.code == "runtime.observation.accepted"
                    for r in later.review.provenance.records
                ),
                "trust": "backend_observed",
                "action_digest": probe_contract.action_digest,
                "contract_id": probe_contract.contract_id,
                "read_contract_id": fs_session.runtime_contract("fs-read").contract_id,
            }
        )
    # Collect only exact sandbox events from an explicitly supplied trusted log.
    network_events = []
    for path in Path(args.ocsf_directory).glob("openshell-ocsf*.log*"):
        with path.open() as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                    if (
                        event.get("container", {}).get("uid") == snapshot.sandbox_id
                        and event.get("time", 0) >= observed_before
                        and event.get("class_uid") in {4001, 4002}
                    ):
                        network_events.append(event)
                except ValueError:
                    continue
    correlation = CorrelationStore(args.correlation_db)
    attached = 0
    correlated: dict[str, list[dict[str, str]]] = {name: [] for name, _ in actions}
    for event in network_events:
        try:
            parsed = parse_openshell_event(event)
        except ValueError:
            continue  # Explicitly unsupported DNS/no-port events remain outside action history.
        matched_name = probe_identity(parsed.metadata)
        if matched_name is None:
            continue
        contract = session.runtime_contract("demo-" + matched_name)
        assert contract.action_id is not None
        # Attribution is established by the host's exclusive test workload and
        # exact invocation window; this is not general destination-based routing.
        correlation.register(
            CorrelationBinding(
                contract.action_id,
                contract.action_digest,
                contract.contract_id,
                source,
                parsed.event_id_digest,
                parsed.event_digest,
                observed_before,
                int(time.time() * 1000) + 60000,
            )
        )
        result = ingest_openshell_event(
            event,
            contract=contract,
            source=source,
            store=correlation,
            now_ms=int(time.time() * 1000),
        )
        if result.observation is not None:
            session.observe_runtime(result.observation)
            attached += 1
            correlated[matched_name].append(
                {"outcome": result.observation.outcome, "trust": result.observation.trust}
            )
    later = session.evaluate(ActionEnvelope.shell("git status --short", action_id="after-probes"))
    assert isinstance(later.review, ActionReview) and later.review.provenance is not None
    records.append(
        {
            "name": "network_evidence_return",
            "passed": any(e["outcome"] == "allowed" for e in correlated["get"])
            and all(
                any(
                    e["outcome"] == "denied" and e["trust"] == "backend_enforced"
                    for e in correlated[name]
                )
                for name in ("post", "unrelated_host")
            )
            and any(
                r.code == "runtime.observation.accepted" for r in later.review.provenance.records
            ),
            "events_attached": attached,
            "correlated_outcomes": correlated,
        }
    )
    return {
        "schema_version": "ordin.openshell_runtime_demo.v1",
        "openshell_version": "0.1.2",
        "runtime": "caller-configured",
        "sandbox_id_digest": digest(snapshot.sandbox_id),
        "policy_digest": snapshot.policy_digest,
        "records": records,
        "passed": all(r["passed"] for r in records),
        "scope": "Actual caller probes plus verified backend readback and protected local evidence correlation. No credential providers, raw commands, response bodies, or secrets are recorded.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sandbox", "filesystem-sandbox", "gateway-endpoint", "correlation-db"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--workspace", default="default")
    parser.add_argument("--openshell", default="openshell")
    parser.add_argument("--ocsf-directory", default="/var/log")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    report = run(args)
    text = json.dumps(report, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
