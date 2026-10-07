"""Strict supported OpenShell authored policy subset and serialization."""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Mapping

from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json, freeze, thaw
from ordin._runtime_url import has_unsafe_authority_characters
from ordin.runtime_contract import _safe_path
from ordin.runtime_requests import NAME, TOOL_NAME, MCP_METHODS, MCP_VERSIONS
from ordin._request_commitment import REQUEST_COMMITMENT_ALGORITHM
from .address_scope import scoped_host, validate_network_scopes

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
HTTP_METHODS = READ_METHODS | {"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}
MAX_PROCESS_IDENTITY = 0xFFFF_FFFE


def public_ipv4_ranges() -> list[str]:
    networks = [ipaddress.IPv4Network("0.0.0.0/0")]
    excluded = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
    ]
    for value in excluded:
        forbidden = ipaddress.IPv4Network(value)
        networks = [
            piece
            for current in networks
            for piece in (
                current.address_exclude(forbidden) if forbidden.subnet_of(current) else (current,)
            )
        ]
    return [str(n) for n in sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))]


PUBLIC_IPV4_RANGES = tuple(public_ipv4_ranges())


def exact_host(host: Any) -> bool:
    import re

    if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host):
        return False
    if host in {
        "localhost",
        "metadata.google.internal",
        "instance-data.ec2.internal",
    } or host.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.version == 4 and address.is_global
    except ValueError:
        return "." in host and not host.endswith(".") and ".." not in host


def exact_request_path(path: Any) -> bool:
    return (
        isinstance(path, str)
        and not has_unsafe_authority_characters(path)
        and _safe_path(path)
        and not any(c in path for c in "%?#")
        and "//" not in path
    )


def policy_errors(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the supported subset without ignoring any unsupported field."""
    errors = []
    try:
        freeze(policy, max_depth=12)
        if len(canonical_json(policy).encode()) > MAX_RUNTIME_BYTES:
            return ("policy.size",)
    except (ValueError, TypeError, RecursionError):
        return ("policy.json",)
    if not isinstance(policy, Mapping):
        return ("policy.type",)
    if set(policy) - {"version", "filesystem_policy", "landlock", "process", "network_policies"}:
        errors.append("policy.unsupported_fields")
    if type(policy.get("version")) is not int or policy.get("version") != 1:
        errors.append("policy.version")
    fs = policy.get("filesystem_policy")
    if not isinstance(fs, Mapping) or set(fs) != {"include_workdir", "read_only", "read_write"}:
        errors.append("filesystem_policy.shape")
    else:
        if fs["include_workdir"] is not False:
            errors.append("filesystem_policy.include_workdir")
        for name in ("read_only", "read_write"):
            paths = fs[name]
            if not isinstance(paths, (list, tuple)) or any(
                not isinstance(p, str) or not _safe_path(p) for p in paths
            ):
                errors.append(f"filesystem_policy.{name}")
        if not fs["read_only"] and not fs["read_write"]:
            # In OpenShell 0.1.2 an empty list disables the Landlock ruleset.
            errors.append("filesystem_policy.empty_disables_isolation")
    if policy.get("landlock") != {"compatibility": "hard_requirement"}:
        errors.append("landlock.compatibility")
    process = policy.get("process")
    if not isinstance(process, Mapping) or set(process) != {"run_as_user", "run_as_group"}:
        errors.append("process.shape")
    elif any(
        not isinstance(process[n], str)
        or not process[n].isascii()
        or not process[n].isdigit()
        or not 1 <= int(process[n]) <= MAX_PROCESS_IDENTITY
        for n in process
    ):
        errors.append("process.non_root_identity")
    rules = policy.get("network_policies")
    if not isinstance(rules, Mapping):
        errors.append("network_policies.shape")
        rules = {}
    for key, rule in rules.items():
        if not isinstance(rule, Mapping) or set(rule) != {"endpoints", "binaries"}:
            errors.append("network_policies.rule_shape")
            continue
        binaries = rule["binaries"]
        if (
            not isinstance(binaries, (list, tuple))
            or not binaries
            or any(
                not isinstance(b, Mapping)
                or set(b) != {"path"}
                or not isinstance(b["path"], str)
                or not _safe_path(b["path"])
                for b in binaries
            )
        ):
            errors.append("network_policies.binary_identity")
        endpoints = rule["endpoints"]
        if not isinstance(endpoints, (tuple, list)) or not endpoints:
            errors.append("network_policies.endpoints")
            continue
        for endpoint in endpoints:
            if not isinstance(endpoint, Mapping) or set(endpoint) - {
                "host",
                "port",
                "protocol",
                "enforcement",
                "rules",
                "allowed_ips",
                "credential_binding",
                "path",
                "mcp",
                "request_integrity",
                "graphql_max_body_bytes",
                "json_rpc",
            }:
                errors.append("network_policies.endpoint_shape")
                continue
            if (
                not scoped_host(endpoint.get("host"))
                or type(endpoint.get("port")) is not int
                or not 1 <= endpoint["port"] <= 65535
            ):
                errors.append("network_policies.endpoint_identity")
            protocol = endpoint.get("protocol")
            if not isinstance(protocol, str):
                errors.append("network_policies.request_inspection")
                continue
            if (
                not isinstance(protocol, str)
                or protocol not in {"rest", "graphql", "mcp", "json-rpc", "tcp"}
                or protocol != "tcp"
                and endpoint.get("enforcement") != "enforce"
            ):
                errors.append("network_policies.request_inspection")
            if protocol in {"graphql", "mcp", "json-rpc"} and not exact_request_path(
                endpoint.get("path")
            ):
                errors.append("network_policies.protocol_path")
            if protocol == "rest" and ("path" in endpoint or "mcp" in endpoint):
                errors.append("network_policies.rest_protocol_fields")
            if protocol == "graphql" and "mcp" in endpoint:
                errors.append("network_policies.mixed_protocol_fields")
            if protocol == "mcp":
                options = endpoint.get("mcp")
                if (
                    not isinstance(options, Mapping)
                    or set(options)
                    != (
                        {"strict_tool_names", "allow_all_known_mcp_methods", "versions"}
                        | ({"max_body_bytes"} if "request_integrity" in endpoint else set())
                    )
                    or "max_body_bytes" in options
                    and (
                        type(options["max_body_bytes"]) is not int
                        or options["max_body_bytes"] != 1_048_576
                    )
                    or options["strict_tool_names"] is not True
                    or options["allow_all_known_mcp_methods"] is not False
                    or not isinstance(options["versions"], (list, tuple))
                    or not options["versions"]
                    or any(not isinstance(v, str) for v in options["versions"])
                    or not set(options["versions"]).issubset(MCP_VERSIONS)
                    or len(set(options["versions"])) != len(options["versions"])
                ):
                    errors.append("network_policies.mcp_options")
            try:
                validate_network_scopes(
                    [
                        {
                            "host": endpoint.get("host"),
                            "port": endpoint.get("port"),
                            "protocols": [protocol],
                            "allowed_ips": endpoint.get("allowed_ips"),
                        }
                    ]
                )
            except (ValueError, TypeError):
                errors.append("network_policies.allowed_ips")
            integrity = endpoint.get("request_integrity")
            if integrity is not None:
                import re

                if (
                    protocol not in {"graphql", "mcp", "json-rpc"}
                    or not isinstance(integrity, Mapping)
                    or set(integrity) != {"algorithm", "commitments"}
                    or integrity["algorithm"] != REQUEST_COMMITMENT_ALGORITHM
                    or not isinstance(integrity["commitments"], (tuple, list))
                    or not 1 <= len(integrity["commitments"]) <= 128
                    or any(
                        not isinstance(c, str) or not re.fullmatch(r"[a-f0-9]{64}", c)
                        for c in integrity["commitments"]
                    )
                    or len(set(integrity["commitments"])) != len(integrity["commitments"])
                ):
                    errors.append("network_policies.request_integrity")
            if protocol == "json-rpc" and integrity is None:
                errors.append("network_policies.request_integrity_required")
            if "graphql_max_body_bytes" in endpoint and (
                protocol != "graphql"
                or integrity is None
                or type(endpoint["graphql_max_body_bytes"]) is not int
                or endpoint["graphql_max_body_bytes"] != 1_048_576
            ):
                errors.append("network_policies.body_limit")
            if "json_rpc" in endpoint and (
                protocol != "json-rpc"
                or integrity is None
                or endpoint["json_rpc"] != {"max_body_bytes": 1_048_576}
            ):
                errors.append("network_policies.body_limit")
            if protocol == "tcp":
                if set(endpoint) != {"host", "port", "protocol", "allowed_ips"}:
                    errors.append("network_policies.tcp_fields")
                continue
            allow = endpoint.get("rules")
            if not isinstance(allow, (list, tuple)) or not allow:
                errors.append("network_policies.request_rules")
            else:
                for entry in allow:
                    value = (
                        entry.get("allow")
                        if isinstance(entry, Mapping) and set(entry) == {"allow"}
                        else None
                    )
                    if protocol == "graphql":
                        if (
                            not isinstance(value, Mapping)
                            or set(value)
                            != (
                                {"operation_type", "fields"}
                                | ({"operation_name"} if "operation_name" in value else set())
                            )
                            or not isinstance(value["operation_type"], str)
                            or value["operation_type"]
                            not in (
                                {"query", "mutation", "subscription"}
                                if integrity is not None
                                else {"query", "mutation"}
                            )
                            or "operation_name" not in value
                            and integrity is None
                            or "operation_name" in value
                            and (
                                not isinstance(value["operation_name"], str)
                                or not NAME.fullmatch(value["operation_name"])
                            )
                            or not isinstance(value["fields"], (list, tuple))
                            or not value["fields"]
                            or any(
                                not isinstance(v, str) or not NAME.fullmatch(v)
                                for v in value["fields"]
                            )
                        ):
                            errors.append("network_policies.graphql_rule_shape")
                    elif protocol == "json-rpc":
                        if (
                            not isinstance(value, Mapping)
                            or set(value) != {"method"}
                            or not isinstance(value["method"], str)
                            or not 1 <= len(value["method"]) <= 128
                            or value["method"] != "*"
                            and any(
                                ord(c) <= 32 or ord(c) == 127 or c == "*" for c in value["method"]
                            )
                        ):
                            errors.append("network_policies.jsonrpc_rule_shape")
                    elif protocol == "mcp":
                        if (
                            not isinstance(value, Mapping)
                            or set(value) - {"method", "params"}
                            or not isinstance(value.get("method"), str)
                            or value["method"] not in MCP_METHODS
                        ):
                            errors.append("network_policies.mcp_rule_shape")
                        elif value["method"] == "tools/call":
                            params = value.get("params")
                            tool_matcher = (
                                params.get("name")
                                if isinstance(params, Mapping) and set(params) == {"name"}
                                else None
                            )
                            if (
                                not isinstance(tool_matcher, Mapping)
                                or set(tool_matcher) != {"any"}
                                or not isinstance(tool_matcher["any"], (list, tuple))
                                or len(tool_matcher["any"]) != 1
                                or not isinstance(tool_matcher["any"][0], str)
                                or not TOOL_NAME.fullmatch(tool_matcher["any"][0])
                            ):
                                errors.append("network_policies.mcp_tool_scope")
                        elif "params" in value:
                            errors.append("network_policies.mcp_params_unsupported")
                    elif (
                        not isinstance(value, Mapping)
                        or set(value) != {"method", "path"}
                        or not isinstance(value["method"], str)
                        or value["method"] not in HTTP_METHODS
                        or not exact_request_path(value["path"])
                    ):
                        errors.append("network_policies.request_rule_shape")
            binding = endpoint.get("credential_binding")
            if binding is not None and (
                not isinstance(binding, Mapping)
                or set(binding) != {"provider"}
                or not isinstance(binding["provider"], str)
                or not binding["provider"]
            ):
                errors.append("credential_binding.shape")
    protocols: dict[tuple[str, int], set[str]] = {}
    for rule in rules.values():
        if not isinstance(rule, Mapping) or not isinstance(rule.get("endpoints"), (list, tuple)):
            continue
        for endpoint in rule["endpoints"]:
            if (
                isinstance(endpoint, Mapping)
                and isinstance(endpoint.get("host"), str)
                and type(endpoint.get("port")) is int
                and isinstance(endpoint.get("protocol"), str)
            ):
                protocols.setdefault((endpoint["host"], endpoint["port"]), set()).add(
                    endpoint["protocol"]
                )
    if any("mcp" in values and len(values) > 1 for values in protocols.values()):
        errors.append("network_policies.mcp_protocol_conflict")
    return tuple(sorted(set(errors)))


def serialize_policy(policy: Mapping[str, Any], *, format: str = "json") -> str:
    errors = policy_errors(policy)
    if errors:
        raise ValueError("openshell_policy_invalid")
    if format == "json":
        return json.dumps(thaw(policy), indent=2, sort_keys=True) + "\n"
    if format != "yaml":
        raise ValueError("unsupported policy output format")
    try:
        import yaml
    except ImportError:
        raise ValueError("openshell_yaml_dependency_missing") from None
    return yaml.safe_dump(thaw(policy), sort_keys=True)


def parse_policy(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_RUNTIME_BYTES:
        raise ValueError("openshell_policy_size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("openshell_policy_duplicate_key")
            result[key] = value
        return result

    try:
        data = json.loads(
            text,
            object_pairs_hook=unique,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("openshell_policy_nonfinite")
            ),
        )
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError:
            raise ValueError("openshell_yaml_dependency_missing") from None
        try:
            if any(
                isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
                for token in yaml.scan(text)
            ):
                raise ValueError("openshell_policy_yaml_alias_unsupported")

            class StrictLoader(yaml.SafeLoader):
                pass

            def mapping(loader, node, deep=False):
                return unique(
                    [
                        (
                            loader.construct_object(k, deep=deep),
                            loader.construct_object(v, deep=deep),
                        )
                        for k, v in node.value
                    ]
                )

            StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
            data = yaml.load(text, Loader=StrictLoader)
        except yaml.YAMLError:
            raise ValueError("openshell_policy_yaml_invalid") from None
    if not isinstance(data, dict) or policy_errors(data):
        raise ValueError("openshell_policy_invalid")
    return data
