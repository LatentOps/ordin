"""Bounded protocol containment composed with the native transport solver."""

from __future__ import annotations

from copy import deepcopy
import ipaddress
from typing import Any

from .address_scope import host_pattern_matches
from .model import policy_errors

EXTENDED_PROTOCOLS = frozenset({"graphql", "mcp", "json-rpc"})


def protocol_domains(policy: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        "network_" + ep["protocol"].replace("-", "_")
        for rule in policy["network_policies"].values()
        for ep in rule["endpoints"]
        if ep["protocol"] in EXTENDED_PROTOCOLS
    ) | frozenset(
        domain
        for _, endpoint in _endpoints(policy)
        if _ip_literal(endpoint)
        for domain in (
            ("network_ip_literal", "network_tcp_literal")
            if endpoint["protocol"] == "tcp"
            else ("network_ip_literal",)
        )
    )


def _ip_literal(endpoint):
    try:
        ipaddress.ip_address(endpoint["host"])
    except ValueError:
        return False
    return True


def _rules_within(candidate, boundary, protocol):
    for entry in candidate:
        rule = entry["allow"]
        within = False
        for allowed_entry in boundary:
            allowed = allowed_entry["allow"]
            if protocol == "rest":
                within = rule == allowed
            elif protocol == "graphql":
                within = (
                    rule["operation_type"] == allowed["operation_type"]
                    and (
                        "operation_name" not in allowed
                        or rule.get("operation_name") == allowed["operation_name"]
                    )
                    and set(rule["fields"]).issubset(allowed["fields"])
                )
            else:
                within = rule["method"] == allowed["method"]
                if "params" in allowed:
                    within = (
                        within
                        and "params" in rule
                        and set(rule["params"]["name"]["any"]).issubset(
                            allowed["params"]["name"]["any"]
                        )
                    )
            if within:
                break
        if not within:
            return False
    return True


def _endpoints(policy):
    return [(rule, ep) for rule in policy["network_policies"].values() for ep in rule["endpoints"]]


def project_transport(policy):
    """Project native domains after exact protocol and IP literal containment.

    Literal grants are proved by the bounded component with their original
    host, port, binary and address range, then omitted from both native inputs.
    The native solver still proves filesystem, process and remaining networking.
    """
    result = deepcopy(policy)
    for name, rule in list(result["network_policies"].items()):
        rule["endpoints"] = [ep for ep in rule["endpoints"] if not _ip_literal(ep)]
        if not rule["endpoints"]:
            del result["network_policies"][name]
    for _, endpoint in _endpoints(result):
        if endpoint["protocol"] in EXTENDED_PROTOCOLS:
            path = endpoint.pop("path")
            endpoint.pop("mcp", None)
            endpoint.pop("request_integrity", None)
            endpoint.pop("graphql_max_body_bytes", None)
            endpoint.pop("json_rpc", None)
            endpoint["protocol"] = "rest"
            endpoint["rules"] = [{"allow": {"method": "POST", "path": path}}]
    return result


def check_protocol_containment(candidate, boundary):
    """Return within/exceeds/unsupported before invoking the transport solver.

    The accepted policy shape is the compiler's bounded shape. Each candidate
    endpoint needs one boundary endpoint containing its complete intersection;
    grants from unrelated endpoints or protocols cannot be combined.
    """
    if policy_errors(candidate) or policy_errors(boundary):
        return "unsupported", "openshell_authority_policy_unsupported"
    for policy in (candidate, boundary):
        seen: dict[tuple[str, int, str], Any] = {}
        for _, endpoint in _endpoints(policy):
            if _ip_literal(endpoint) and not endpoint["allowed_ips"]:
                return "unsupported", "openshell_authority_literal_address_required"
            key = (endpoint["host"], endpoint["port"], endpoint.get("path", ""))
            config = (endpoint["protocol"], endpoint.get("request_integrity"), endpoint.get("mcp"))
            if key in seen and seen[key] != config:
                return "unsupported", "openshell_authority_endpoint_ambiguous"
            seen[key] = config
    for rule, endpoint in _endpoints(candidate):
        protocol = endpoint["protocol"]
        integrity = endpoint.get("request_integrity")
        if protocol in EXTENDED_PROTOCOLS and integrity is None:
            return "unsupported", "openshell_authority_commitment_required"
        matched = False
        for allowed_rule, allowed in _endpoints(boundary):
            if (
                allowed["protocol"] not in {protocol, "tcp"}
                or allowed["port"] != endpoint["port"]
                or protocol in EXTENDED_PROTOCOLS
                and allowed["protocol"] != "tcp"
                and allowed.get("path") != endpoint["path"]
                or not host_pattern_matches(allowed["host"], endpoint["host"])
                or not {b["path"] for b in rule["binaries"]}.issubset(
                    b["path"] for b in allowed_rule["binaries"]
                )
            ):
                continue
            candidate_ips = [ipaddress.ip_network(value) for value in endpoint["allowed_ips"]]
            maximum_ips = [ipaddress.ip_network(value) for value in allowed["allowed_ips"]]
            maximum_ips = [
                *ipaddress.collapse_addresses(
                    n for n in maximum_ips if isinstance(n, ipaddress.IPv4Network)
                ),
                *ipaddress.collapse_addresses(
                    n for n in maximum_ips if isinstance(n, ipaddress.IPv6Network)
                ),
            ]
            if not all(
                any(
                    (
                        isinstance(c, ipaddress.IPv4Network)
                        and isinstance(b, ipaddress.IPv4Network)
                        and c.subnet_of(b)
                    )
                    or (
                        isinstance(c, ipaddress.IPv6Network)
                        and isinstance(b, ipaddress.IPv6Network)
                        and c.subnet_of(b)
                    )
                    for b in maximum_ips
                )
                for c in candidate_ips
            ):
                continue
            maximum = allowed.get("request_integrity")
            if maximum is not None and (
                integrity is None
                or maximum["algorithm"] != integrity["algorithm"]
                or not set(integrity["commitments"]).issubset(maximum["commitments"])
            ):
                continue
            if (
                protocol == "mcp"
                and allowed["protocol"] == "mcp"
                and not set(endpoint["mcp"]["versions"]).issubset(allowed["mcp"]["versions"])
            ):
                continue
            if (
                protocol == "tcp"
                or allowed["protocol"] == "tcp"
                or _rules_within(endpoint["rules"], allowed["rules"], protocol)
            ):
                matched = True
                break
        if not matched:
            return "exceeds_boundary", "openshell_request_authority_exceeds_boundary"
    return "within_boundary", "openshell_request_authority_within"
