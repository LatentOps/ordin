"""Explicit, bounded OpenShell management calls; reviewed actions never enter argv."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Sequence
from urllib.parse import urlsplit

from ordin._runtime_json import MAX_RUNTIME_BYTES, freeze
from ordin._runtime_url import has_unsafe_authority_characters

SUPPORTED_CLI_VERSION = "0.1.2"


class OpenShellCommandError(ValueError):
    def __init__(self, reason_code: str, *, uncertain: bool = False) -> None:
        self.reason_code, self.uncertain = reason_code, uncertain
        super().__init__(reason_code)


def identifier(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("openshell_target_identity_invalid")


def load_json(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode()) > MAX_RUNTIME_BYTES:
        raise ValueError("openshell_json_size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("openshell_json_duplicate_key")
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=unique)
        freeze(data, max_depth=14)  # Management JSON wraps nested policy selectors.
        if not isinstance(data, dict):
            raise ValueError("openshell_json_object_required")
    except (TypeError, RecursionError):
        raise ValueError("openshell_json_invalid") from None
    return data


@dataclass(frozen=True)
class OpenShellCLI:
    executable: str = "openshell"
    gateway: str | None = None
    workspace: str = "default"
    gateway_endpoint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or not self.executable:
            raise ValueError("openshell_cli_identity_invalid")
        if self.gateway is not None:
            identifier(self.gateway)
        identifier(self.workspace)
        if self.gateway_endpoint is not None:
            try:
                if not isinstance(self.gateway_endpoint, str) or has_unsafe_authority_characters(
                    self.gateway_endpoint
                ):
                    raise ValueError("openshell_gateway_endpoint_invalid")
                parsed = urlsplit(self.gateway_endpoint)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.query
                    or parsed.fragment
                    or parsed.path not in {"", "/"}
                    or parsed.port is not None
                    and not 1 <= parsed.port <= 65535
                ):
                    raise ValueError("openshell_gateway_endpoint_invalid")
            except (TypeError, ValueError):
                raise ValueError("openshell_gateway_endpoint_invalid") from None

    @property
    def context(self) -> dict[str, str | None]:
        return {
            "executable": self.executable,
            "gateway": self.gateway,
            "workspace": self.workspace,
            "gateway_endpoint": self.gateway_endpoint,
        }

    def run(self, arguments: Sequence[str], *, timeout: float = 30) -> str:
        """Run management argv only, with no shell, stdin, or raw diagnostic output."""
        if not 0 < timeout <= 60:
            raise ValueError("openshell_command_timeout_invalid")
        if not isinstance(arguments, (tuple, list)):
            raise OpenShellCommandError("openshell_management_command_unsupported")
        argv = tuple(arguments)
        if any(not isinstance(a, str) or len(a) > 4096 or "\0" in a for a in argv):
            raise OpenShellCommandError("openshell_management_command_unsupported")
        valid = argv == ("--version",)
        if len(argv) >= 3 and argv[:2] in {
            ("policy", "get"),
            ("policy", "set"),
            ("sandbox", "get"),
        }:
            identifier(argv[2])
            valid = (
                argv[:2] == ("policy", "get")
                and (
                    argv[3:] == ("--full", "--output", "json")
                    or (
                        len(argv) == 8
                        and argv[3] == "--rev"
                        and argv[4].isdigit()
                        and argv[5:] == ("--full", "--output", "json")
                    )
                )
                or argv[:2] == ("sandbox", "get")
                and argv[3:] == ("--output", "json")
                or argv[:2] == ("policy", "set")
                and len(argv) == 8
                and argv[3] == "--policy"
                and bool(argv[4])
                and argv[5:7] == ("--wait", "--timeout")
                and argv[7].isdigit()
            )
        if not valid:
            raise OpenShellCommandError("openshell_management_command_unsupported")
        located = shutil.which(self.executable)
        if located is None:
            raise OpenShellCommandError("openshell_cli_missing")
        context = ["--workspace", self.workspace]
        if self.gateway is not None:
            context.extend(("--gateway", self.gateway))
        if self.gateway_endpoint is not None:
            context.extend(("--gateway-endpoint", self.gateway_endpoint))
        try:
            with tempfile.TemporaryFile() as output:
                process = subprocess.run(
                    [located, *context, *argv],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
                output.seek(0)
                content = output.read(MAX_RUNTIME_BYTES + 1)
            if len(content) > MAX_RUNTIME_BYTES:
                raise OpenShellCommandError("openshell_cli_output_size", uncertain=True)
            if process.returncode != 0:
                raise OpenShellCommandError("openshell_cli_failed", uncertain=True)
            return content.decode("utf-8")
        except subprocess.TimeoutExpired:
            raise OpenShellCommandError("openshell_cli_timeout", uncertain=True) from None
        except (OSError, UnicodeError):
            raise OpenShellCommandError("openshell_cli_unavailable", uncertain=True) from None

    def require_compatible(self) -> None:
        if self.run(("--version",), timeout=5).strip() != f"openshell {SUPPORTED_CLI_VERSION}":
            raise OpenShellCommandError("openshell_cli_compatibility")

    def json(self, arguments: Sequence[str], *, timeout: float = 30) -> dict[str, Any]:
        try:
            return load_json(self.run(arguments, timeout=timeout))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, OpenShellCommandError):
                raise
            raise OpenShellCommandError("openshell_cli_json_invalid") from None
