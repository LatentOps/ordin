"""Explicit host approval of destination address ranges; no DNS inference."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping

_FORBIDDEN = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/3",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
        "::ffff:0:0/96",
        "fd00:ec2::254/128",
        "100.100.100.200/32",
    )
)


def scoped_host(host: Any) -> bool:
    if (
        not isinstance(host, str)
        or len(host) > 253
        or host != host.lower()
        or host.endswith(".")
        or "%" in host
    ):
        return False
    if host in {
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "localhost",
        "host.openshell.internal",
        "host.containers.internal",
        "host.docker.internal",
    } or host.endswith(".localhost"):
        return False
    try:
        address = ipaddress.ip_address(host)
        return str(address) == host and not any(
            address.version == net.version and address in net for net in _FORBIDDEN
        )
    except ValueError:
        return "." in host and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )


def host_pattern_matches(pattern: str, host: str | None) -> bool:
    if not isinstance(pattern, str) or not isinstance(host, str):
        return False
    if pattern.startswith("**."):
        suffix = pattern[3:]
        return scoped_host(suffix) and host.endswith("." + suffix)
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return (
            scoped_host(suffix)
            and host.endswith("." + suffix)
            and len(host.split(".")) == len(suffix.split(".")) + 1
        )
    return pattern == host and scoped_host(pattern)


def validate_network_scopes(scopes: Any) -> None:
    if not isinstance(scopes, (list, tuple)) or len(scopes) > 128:
        raise ValueError("openshell_network_scope_invalid")
    for scope in scopes:
        if (
            not isinstance(scope, Mapping)
            or set(scope) != {"host", "port", "protocols", "allowed_ips"}
            or not isinstance(scope["host"], str)
            or not scoped_host(scope["host"].removeprefix("**.").removeprefix("*."))
            or type(scope["port"]) is not int
            or not 1 <= scope["port"] <= 65535
            or not isinstance(scope["protocols"], (tuple, list))
            or not scope["protocols"]
            or not set(scope["protocols"]).issubset({"rest", "graphql", "mcp", "json-rpc", "tcp"})
            or not isinstance(scope["allowed_ips"], (tuple, list))
            or not 1 <= len(scope["allowed_ips"]) <= 128
        ):
            raise ValueError("openshell_network_scope_invalid")
        networks = []
        for value in scope["allowed_ips"]:
            try:
                if not isinstance(value, str) or "%" in value:
                    raise ValueError
                network = ipaddress.ip_network(value, strict=True)
                if any(
                    network.version == forbidden.version and network.overlaps(forbidden)
                    for forbidden in _FORBIDDEN
                ):
                    raise ValueError
                networks.append(str(network))
            except ValueError:
                raise ValueError("openshell_network_scope_invalid") from None
        if len(set(networks)) != len(networks):
            raise ValueError("openshell_network_scope_invalid")


def approved_addresses(scopes, host: str | None, port: int | None, protocol: str):
    matches = [
        scope
        for scope in scopes
        if scope["port"] == port
        and protocol in scope["protocols"]
        and host_pattern_matches(scope["host"], host)
    ]
    if not matches:
        return None
    # Every matching host approval constrains the result. Conflicting approvals
    # require an explicit host resolution instead of a silent union.
    values = {
        tuple(sorted(str(ipaddress.ip_network(value)) for value in scope["allowed_ips"]))
        for scope in matches
    }
    if len(values) != 1:
        raise ValueError("openshell_network_scope_conflict")
    return next(iter(values))
