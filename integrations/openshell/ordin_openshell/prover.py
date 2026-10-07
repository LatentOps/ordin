"""Explicit standalone prover invocation with strict JSON/version/coverage checks."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from ordin._runtime_json import MAX_RUNTIME_BYTES, digest, freeze, thaw

SUPPORTED_PROVER_VERSION = "0.1.2"
MODELED_DOMAINS = frozenset({"filesystem", "network_l4", "network_rest", "process", "landlock"})
EXIT_CODES = {
    "within_boundary": 0,
    "exceeds_boundary": 1,
    "unsupported": 3,
    "inconclusive": 3,
    "error": 2,
}


@dataclass(frozen=True)
class OpenShellProverResult:
    result: str
    reason_code: str
    coverage: Mapping[str, Any] = field(default_factory=dict)
    counterexample: Mapping[str, Any] | None = None
    candidate_digest: str | None = None
    boundary_digest: str | None = None
    prover_version: str | None = None
    unsupported_domains: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.result not in EXIT_CODES:
            raise ValueError("invalid prover result")
        object.__setattr__(self, "coverage", freeze(self.coverage))
        object.__setattr__(self, "counterexample", freeze(self.counterexample))
        object.__setattr__(self, "unsupported_domains", tuple(self.unsupported_domains))
        if self.result == "within_boundary" and self.unsupported_domains:
            raise ValueError("prover success cannot omit required domains")

    @property
    def ok(self) -> bool:
        return self.result == "within_boundary"

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "reason_code": self.reason_code,
            "coverage": thaw(self.coverage),
            "counterexample": thaw(self.counterexample),
            "candidate_digest": self.candidate_digest,
            "boundary_digest": self.boundary_digest,
            "prover_version": self.prover_version,
            "unsupported_domains": list(self.unsupported_domains),
        }


def parse_prover_json(
    output: str,
    *,
    returncode: int,
    required_domains: frozenset[str] = MODELED_DOMAINS,
    candidate_digest: str | None = None,
    boundary_digest: str | None = None,
) -> OpenShellProverResult:
    def failure(code: str) -> OpenShellProverResult:
        return OpenShellProverResult(
            "error", code, candidate_digest=candidate_digest, boundary_digest=boundary_digest
        )

    if len(output.encode()) > MAX_RUNTIME_BYTES:
        return failure("openshell_prover_output_size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate prover JSON field")
            result[key] = value
        return result

    try:
        data = json.loads(output, object_pairs_hook=unique)
        freeze(data)
    except (ValueError, TypeError, RecursionError):
        return failure("openshell_prover_json_invalid")
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "prover_version",
        "check",
        "coverage",
        "result",
        "exit_code",
        "inputs",
        "counterexample",
        "reason_code",
        "reason",
    }:
        return failure("openshell_prover_compatibility")
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["prover_version"] != SUPPORTED_PROVER_VERSION
        or data["check"] != "boundary"
    ):
        return failure("openshell_prover_compatibility")
    state = data["result"]
    if (
        not isinstance(state, str)
        or state not in EXIT_CODES
        or type(data["exit_code"]) is not int
        or data["exit_code"] != EXIT_CODES[state]
        or returncode != data["exit_code"]
    ):
        return failure("openshell_prover_exit_mismatch")
    coverage = data["coverage"]
    if coverage is None:
        coverage = {"domains": []}
    if (
        not isinstance(coverage, dict)
        or set(coverage) != {"domains"}
        or not isinstance(coverage["domains"], list)
        or any(not isinstance(d, str) for d in coverage["domains"])
    ):
        return failure("openshell_prover_coverage_invalid")
    counter = data["counterexample"]
    if counter is not None and (not isinstance(counter, dict) or "domain" not in counter):
        return failure("openshell_prover_counterexample_invalid")
    missing = tuple(sorted(required_domains - set(coverage["domains"])))
    code = data["reason_code"] or f"openshell_prover_{state}"
    if not isinstance(code, str):
        return failure("openshell_prover_reason_invalid")
    if state == "within_boundary" and missing:
        state, code = "unsupported", "openshell_prover_coverage_incomplete"
    return OpenShellProverResult(
        state,
        code,
        coverage,
        counter,
        candidate_digest,
        boundary_digest,
        data["prover_version"],
        missing,
    )


def _policy_bytes(path: str | Path) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("policy must be a regular file")
    with target.open("rb") as source:
        data = source.read(MAX_RUNTIME_BYTES + 1)
    if len(data) > MAX_RUNTIME_BYTES:
        raise ValueError("policy exceeds byte limit")
    return data


def verify_with_openshell_prover(
    candidate_policy_path: str | Path,
    boundary_policy_path: str | Path,
    *,
    executable: str = "openshell-prover",
    timeout: float = 15,
    required_domains: frozenset[str] = MODELED_DOMAINS,
    _transport_component: bool = False,
) -> OpenShellProverResult:
    """Snapshot inputs, invoke the prover only, and retain exact input digests."""
    import hashlib

    if not 0 < timeout <= 60:
        raise ValueError("prover timeout must be between zero and 60 seconds")
    located = shutil.which(executable)
    if located is None:
        return OpenShellProverResult("error", "openshell_prover_missing")
    try:
        candidate, boundary = (
            _policy_bytes(candidate_policy_path),
            _policy_bytes(boundary_policy_path),
        )
    except (OSError, ValueError):
        return OpenShellProverResult("error", "openshell_prover_input_invalid")
    c_digest, b_digest = hashlib.sha256(candidate).hexdigest(), hashlib.sha256(boundary).hexdigest()
    if not _transport_component:
        from .authority_prover import (
            check_protocol_containment,
            project_transport,
            protocol_domains,
        )
        from .model import parse_policy

        try:
            c_policy, b_policy = (
                parse_policy(candidate.decode("utf-8")),
                parse_policy(boundary.decode("utf-8")),
            )
            domains = protocol_domains(c_policy) | protocol_domains(b_policy)
            if domains:
                state, code = check_protocol_containment(c_policy, b_policy)
                if state != "within_boundary":
                    return OpenShellProverResult(
                        state,
                        code,
                        {"domains": []},
                        candidate_digest=c_digest,
                        boundary_digest=b_digest,
                    )
                with tempfile.TemporaryDirectory(prefix="ordin-authority-proof-") as directory:
                    paths = [Path(directory) / name for name in ("candidate.json", "boundary.json")]
                    for path, policy in zip(paths, (c_policy, b_policy)):
                        path.write_text(
                            json.dumps(
                                project_transport(policy), sort_keys=True, separators=(",", ":")
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        path.chmod(0o600)
                    component = verify_with_openshell_prover(
                        *paths,
                        executable=executable,
                        timeout=timeout,
                        required_domains=required_domains - domains - {"request_integrity"},
                        _transport_component=True,
                    )
                covered = (
                    set(component.coverage.get("domains", ()))
                    | set(domains)
                    | ({"request_integrity"} if domains - {"network_tcp_literal"} else set())
                )
                missing = tuple(sorted(required_domains - covered))
                return OpenShellProverResult(
                    "unsupported" if component.ok and missing else component.result,
                    "openshell_prover_coverage_incomplete"
                    if component.ok and missing
                    else "openshell_composed_authority_within"
                    if component.ok
                    else component.reason_code,
                    {
                        "domains": sorted(covered),
                        "composition": "ordin.request-authority.v1",
                        "transport_candidate_digest": component.candidate_digest,
                        "transport_boundary_digest": component.boundary_digest,
                    },
                    component.counterexample,
                    c_digest,
                    b_digest,
                    component.prover_version,
                    missing,
                )
        except (UnicodeError, ValueError, TypeError, KeyError):
            # Legacy authored policies keep their native parser/prover behavior.
            # Extended policies must never be projected after failed validation.
            if b"request_integrity" in candidate or b"request_integrity" in boundary:
                return OpenShellProverResult(
                    "unsupported",
                    "openshell_authority_policy_unsupported",
                    candidate_digest=c_digest,
                    boundary_digest=b_digest,
                )
    try:
        with tempfile.TemporaryDirectory(prefix="ordin-prover-") as directory:
            c_path, b_path = (
                Path(directory) / "candidate.policy",
                Path(directory) / "boundary.policy",
            )
            c_path.write_bytes(candidate)
            b_path.write_bytes(boundary)
            c_path.chmod(0o600)
            b_path.chmod(0o600)
            with tempfile.TemporaryFile() as output:
                process = subprocess.run(
                    [
                        located,
                        "check",
                        str(c_path),
                        "--boundary",
                        str(b_path),
                        "--output",
                        "json",
                        "--timeout",
                        f"{max(1, int(timeout * 1000) - 1000)}ms",
                    ],
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
                output.seek(0)
                text = output.read(MAX_RUNTIME_BYTES + 1).decode("utf-8")
        return parse_prover_json(
            text,
            returncode=process.returncode,
            required_domains=required_domains,
            candidate_digest=c_digest,
            boundary_digest=b_digest,
        )
    except subprocess.TimeoutExpired:
        return OpenShellProverResult(
            "inconclusive",
            "openshell_prover_timeout",
            candidate_digest=c_digest,
            boundary_digest=b_digest,
        )
    except (OSError, UnicodeError):
        return OpenShellProverResult(
            "error",
            "openshell_prover_unavailable",
            candidate_digest=c_digest,
            boundary_digest=b_digest,
        )
