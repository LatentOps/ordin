"""Compatibility gate for the audited local runtime extension and actual guest."""

from __future__ import annotations

from importlib.resources import files
import json
import re

EXTENSION_ID = "ordin.request-authority.v1"


def expected_runtime_identity():
    try:
        value = json.loads(
            files("ordin_openshell").joinpath("runtime_identity.json").read_text(encoding="utf-8")
        )
        if (
            not isinstance(value, dict)
            or value.get("extension_id") != EXTENSION_ID
            or value.get("upstream_revision") != "6648bd0c290efbc41ba131ee9831ee45cd431f94"
            or not isinstance(value.get("source_digest"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["source_digest"])
        ):
            raise ValueError
        return value
    except (OSError, ValueError, TypeError):
        raise ValueError("openshell_runtime_extension_unavailable") from None


def require_runtime_identity(identity, *, require_staged_tcp=False):
    expected = expected_runtime_identity()
    if identity.get("runtime_extension_id") != EXTENSION_ID or any(
        identity.get(key) != expected["source_digest"]
        for key in ("runtime_source_digest", "gateway_source_digest", "cli_source_digest")
    ):
        raise ValueError("openshell_runtime_extension_mismatch")
    if require_staged_tcp and (
        identity.get("staged_tcp_confirmed") is not True
        or identity.get("egress_interception") != "seccomp-notify"
        or identity.get("request_attribution") != "seccomp-notify-procfs"
        or not identity.get("confirmed_backend")
    ):
        raise ValueError("openshell_staged_tcp_confirmation_required")


def has_tcp_literals(contract):
    import ipaddress

    for network in contract.network:
        if network.protocol == "tcp":
            try:
                ipaddress.ip_address(network.host)
                return True
            except (ValueError, TypeError):
                pass
    return False
