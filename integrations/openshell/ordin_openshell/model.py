"""Strict supported OpenShell authored policy subset and serialization."""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Mapping

from ordin._runtime_json import MAX_RUNTIME_BYTES, canonical_json, freeze, thaw
from ordin.runtime_contract import _safe_path

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
        and _safe_path(path)
        and not any(c in path for c in "%?#")
        and "//" not in path
    )


def policy_errors(policy: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the supported subset without ignoring any unsupported field."""
    errors = []
    try:
        freeze(policy)
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
            }:
                errors.append("network_policies.endpoint_shape")
                continue
            if (
                not exact_host(endpoint.get("host"))
                or type(endpoint.get("port")) is not int
                or not 1 <= endpoint["port"] <= 65535
            ):
                errors.append("network_policies.endpoint_identity")
            if endpoint.get("protocol") != "rest" or endpoint.get("enforcement") != "enforce":
                errors.append("network_policies.request_inspection")
            if tuple(endpoint.get("allowed_ips", ())) != PUBLIC_IPV4_RANGES:
                errors.append("network_policies.allowed_ips")
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
                    if (
                        not isinstance(value, Mapping)
                        or set(value) != {"method", "path"}
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
