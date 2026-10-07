"""Compatibility diagnostics use version/schema probes only; no sandbox is mutated."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json

from . import (
    __version__,
    TESTED_OPENSHELL_VERSION,
    POLICY_SCHEMA_VERSION,
    PROVER_JSON_SCHEMA_VERSION,
)
from .model import PUBLIC_IPV4_RANGES, policy_errors
from .prover import verify_with_openshell_prover


def _version(executable: str, product: str) -> dict[str, Any]:
    located = shutil.which(executable)
    if located is None:
        return {
            "available": False,
            "compatible": False,
            "version": None,
            "reason_code": product.replace("-", "_") + "_missing",
        }
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.run(
                [located, "--version"],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            output.seek(0)
            raw = output.read(MAX_RUNTIME_BYTES + 1)
        text = raw.decode().strip() if len(raw) <= MAX_RUNTIME_BYTES else ""
        compatible = process.returncode == 0 and text == product + " " + TESTED_OPENSHELL_VERSION
        return {
            "available": True,
            "compatible": compatible,
            "version": TESTED_OPENSHELL_VERSION if compatible else None,
            "reason_code": "openshell_version_supported"
            if compatible
            else "openshell_version_unsupported",
        }
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return {
            "available": True,
            "compatible": False,
            "version": None,
            "reason_code": "openshell_version_probe_failed",
        }


def openshell_doctor(
    *,
    cli_executable: str = "openshell",
    prover_executable: str = "openshell-prover",
    sandbox: str | None = None,
    gateway: str | None = None,
    gateway_endpoint: str | None = None,
    workspace: str = "default",
) -> dict[str, Any]:
    cli, prover = (
        _version(cli_executable, "openshell"),
        _version(prover_executable, "openshell-prover"),
    )
    policy = {
        "version": 1,
        "filesystem_policy": {"include_workdir": False, "read_only": ["/usr"], "read_write": []},
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": "1000", "run_as_group": "1000"},
        "network_policies": {
            "doctor_probe": {
                "binaries": [{"path": "/usr/bin/curl"}],
                "endpoints": [
                    {
                        "host": "api.github.com",
                        "port": 443,
                        "protocol": "rest",
                        "enforcement": "enforce",
                        "allowed_ips": list(PUBLIC_IPV4_RANGES),
                        "rules": [{"allow": {"method": "GET", "path": "/rate_limit"}}],
                    }
                ],
            }
        },
    }
    schema = {
        "compatible": not policy_errors(policy),
        "reason_code": "openshell_compiler_schema_valid",
        "prover_checked": False,
    }
    if prover["compatible"]:
        try:
            with tempfile.TemporaryDirectory(prefix="ordin-openshell-doctor-") as directory:
                path = Path(directory) / "schema-probe.json"
                path.write_text(canonical_json(policy), encoding="utf-8")
                path.chmod(0o600)
                proof = verify_with_openshell_prover(path, path, executable=prover_executable)
            schema = {
                "compatible": proof.ok,
                "reason_code": proof.reason_code,
                "prover_checked": True,
                "coverage": proof.as_dict()["coverage"],
            }
        except (OSError, ValueError):
            schema = {
                "compatible": False,
                "reason_code": "openshell_schema_probe_failed",
                "prover_checked": False,
            }
    from .extension import expected_runtime_identity, require_runtime_identity
    from .backend_cli import OpenShellCLI, OpenShellCommandError

    extension = {
        "compatible": False,
        "checked": False,
        "reason_code": "openshell_runtime_extension_target_required",
    }
    try:
        expected = expected_runtime_identity()
        extension["expected_source_digest"] = expected["source_digest"]
        if sandbox is not None:
            manager = OpenShellCLI(cli_executable, gateway, workspace, gateway_endpoint)
            manager.require_compatible()
            detail = manager.json(("sandbox", "get", sandbox, "--output", "json"))
            admission = detail.get("configuration_admission", {})
            if detail.get("phase") != "Ready" or admission.get("state") != "accepted":
                raise ValueError("openshell_runtime_not_admitted")
            require_runtime_identity(admission)
            extension.update(
                compatible=True, checked=True, reason_code="openshell_runtime_extension_supported"
            )
    except (ValueError, OpenShellCommandError) as error:
        extension.update(checked=sandbox is not None, reason_code=str(error))
    ok = (
        cli["compatible"]
        and prover["compatible"]
        and schema["compatible"]
        and (sandbox is None or extension["compatible"])
    )
    return {
        "status": "success" if ok else "unsupported",
        "sandbox_mutated": False,
        "compatibility": {
            "integration_version": __version__,
            "tested_openshell_version": TESTED_OPENSHELL_VERSION,
            "policy_schema_version": POLICY_SCHEMA_VERSION,
            "prover_json_schema_version": PROVER_JSON_SCHEMA_VERSION,
        },
        "checks": {
            "cli": cli,
            "prover": prover,
            "compiler_schema": schema,
            "yaml": {"available": importlib.util.find_spec("yaml") is not None, "required": False},
            "runtime_extension": extension,
        },
    }
