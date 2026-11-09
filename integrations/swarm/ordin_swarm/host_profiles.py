"""Explicit, private operator configuration for the managed tool host.

Loading a profile inspects data. Only the explicit host entry point constructs
live authority, starts workers or opens a transport.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import urlsplit

from ordin.assurance._files import read_scoped_file, relative_parts
from ordin._runtime_json import digest
from ordin.schema import validate_named_schema


PROFILE_VERSION = "ordin.swarm_tool_host_profile.v1"
HOST_TOOL_DATA_BYTES = 16384
LABELS = frozenset({"public", "private_code", "secret", "pii", "unclassified"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_RESERVED = frozenset({"broker", "operator", "authority-root", "server", "ca"})


def _identifier(value: Any, field: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid host {field}")
    return value


def _counter(value: Any, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid host {field}")
    return value


def _shape(value: Any, fields: set[str], field: str, *, optional=frozenset()) -> dict[str, Any]:
    if type(value) is not dict or not fields <= set(value) <= fields | set(optional):
        raise ValueError(f"invalid host {field} fields")
    return value


def _flat(value: Any) -> str:
    if type(value) is not str or len(value) > 128 or len(relative_parts(value)) != 1:
        raise ValueError("host file must be one exact workspace name")
    return value


def _items(value: Any, field: str, *, maximum: int = 64) -> tuple[str, ...]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"invalid host {field} inventory")
    if any(type(item) is not str for item in value) or len(set(value)) != len(value):
        raise ValueError(f"duplicate or invalid host {field}")
    return tuple(value)


def _absolute(value: Any, field: str) -> Path:
    if type(value) is not str or len(value) > 4096 or "\x00" in value:
        raise ValueError(f"invalid host {field}")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or value.startswith(("\\\\", "//")):
        raise ValueError(f"host {field} must be an explicit local absolute path")
    return path


@dataclass(frozen=True, slots=True)
class HostFile:
    name: str
    label: str

    @classmethod
    def parse(cls, value: Any) -> HostFile:
        row = _shape(value, {"name", "label"}, "file")
        name = _flat(row["name"])
        if type(row["label"]) is not str or row["label"] not in LABELS:
            raise ValueError("invalid host file classification")
        return cls(name, row["label"])


@dataclass(frozen=True, slots=True)
class HostHTTPRoute:
    route_id: str
    url: str
    addresses: tuple[str, ...]
    allow_private_network: bool
    allow_http: bool
    response_limit_bytes: int
    response_label: str
    credential_file: str | None
    ca_file: str | None

    @classmethod
    def parse(cls, value: Any) -> HostHTTPRoute:
        row = _shape(
            value,
            {
                "route_id",
                "url",
                "addresses",
                "allow_private_network",
                "allow_http",
                "response_limit_bytes",
                "response_label",
                "credential_file",
                "ca_file",
            },
            "HTTP route",
        )
        route_id = _identifier(row["route_id"], "HTTP route identity")
        url = row["url"]
        if (
            type(url) is not str
            or not 1 <= len(url) <= 2048
            or any(ord(char) < 33 or ord(char) == 127 for char in url)
        ):
            raise ValueError("invalid exact host HTTP URL")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            raise ValueError("invalid exact host HTTP authority") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
            or "@" in parsed.netloc
            or not parsed.hostname.isascii()
            or parsed.hostname.endswith(".")
            or "%" in parsed.hostname
            or port == 0
            or parsed.path not in {"", "/"}
            and (
                "\\" in parsed.path
                or "%" in parsed.path
                or "//" in parsed.path
                or any(part in {".", ".."} for part in parsed.path.split("/"))
            )
        ):
            raise ValueError("host HTTP route must have an unambiguous exact authority/path")
        private = row["allow_private_network"]
        plain = row["allow_http"]
        addresses = _items(row["addresses"], "pinned IP addresses", maximum=16)
        if type(private) is not bool or type(plain) is not bool or not addresses:
            raise ValueError("host HTTP route requires explicit address and transport scope")
        for address in addresses:
            parsed_ip = ipaddress.ip_address(address)
            if (
                str(parsed_ip) != address
                or parsed_ip.is_multicast
                or parsed_ip.is_unspecified
                or getattr(parsed_ip, "ipv4_mapped", None) is not None
                or not parsed_ip.is_global
                and not private
            ):
                raise ValueError("host HTTP route contains an unauthorized pinned address")
        if parsed.scheme == "http" and (
            not plain
            or not private
            or not all(ipaddress.ip_address(ip).is_loopback for ip in addresses)
        ):
            raise ValueError("plaintext HTTP is limited to explicitly owned loopback routes")
        credential = row["credential_file"]
        if credential is not None:
            relative_parts(credential)
            if parsed.scheme != "https":
                raise ValueError("host credentials require verified HTTPS")
        ca_file = row["ca_file"]
        if ca_file is not None:
            relative_parts(ca_file)
            if parsed.scheme != "https":
                raise ValueError("host trust material requires HTTPS")
        if type(row["response_label"]) is not str or row["response_label"] not in LABELS:
            raise ValueError("host HTTP response requires an operator classification")
        return cls(
            route_id,
            url,
            addresses,
            private,
            plain,
            _counter(row["response_limit_bytes"], "response limit", 1, 65536),
            row["response_label"],
            credential,
            ca_file,
        )


@dataclass(frozen=True, slots=True)
class HostActor:
    agent_id: str
    read_files: tuple[str, ...]
    write_files: tuple[str, ...]
    http_routes: tuple[str, ...]
    peers: tuple[str, ...]
    test_ids: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: Any) -> HostActor:
        row = _shape(
            value,
            {"agent_id", "read_files", "write_files", "http_routes", "peers"},
            "actor",
            optional={"test_ids"},
        )
        agent_id = _identifier(row["agent_id"], "agent identity")
        if agent_id in _RESERVED:
            raise ValueError("reserved host agent identity")
        reads = _items(row["read_files"], "read files")
        writes = _items(row["write_files"], "write files")
        routes = _items(row["http_routes"], "HTTP routes", maximum=16)
        peers = _items(row["peers"], "message peers", maximum=16)
        tests = _items(row.get("test_ids", []), "test routes", maximum=16)
        for name in (*reads, *writes):
            _flat(name)
        for name in (*routes, *peers, *tests):
            _identifier(name, "route or peer")
        if agent_id in peers:
            raise ValueError("self-directed host message route")
        return cls(agent_id, reads, writes, routes, peers, tests)


@dataclass(frozen=True, slots=True)
class HostTestRoute:
    test_id: str
    selectors: tuple[str, ...]

    @classmethod
    def parse(cls, value):
        row = _shape(value, {"test_id", "selectors"}, "fixed test route")
        test_id = _identifier(row["test_id"], "test identity")
        selectors = _items(row["selectors"], "fixed test selectors", maximum=16)
        if not selectors or any(
            len(value) > 256
            or re.fullmatch(r"[A-Za-z0-9_.-]+\.py(?:::[A-Za-z0-9_]+)*", value) is None
            or value.startswith(("/", "-"))
            for value in selectors
        ):
            raise ValueError("test selectors must name fixed managed Python file node IDs")
        return cls(test_id, selectors)


@dataclass(frozen=True, slots=True)
class HostLimits:
    requests: int
    output_bytes: int
    concurrency: int
    lifetime_seconds: int

    @classmethod
    def parse(cls, value: Any) -> HostLimits:
        row = _shape(
            value, {"requests", "output_bytes", "concurrency", "lifetime_seconds"}, "limits"
        )
        return cls(
            _counter(row["requests"], "request budget", 1, 100000),
            _counter(row["output_bytes"], "output budget", 1, 16777216),
            _counter(row["concurrency"], "concurrency", 1, 16),
            _counter(row["lifetime_seconds"], "task lifetime", 1, 3600),
        )


@dataclass(frozen=True, slots=True)
class ToolHostProfile:
    profile_id: str
    tenant_id: str
    swarm_id: str
    task_id: str
    workspace: Path
    files: tuple[HostFile, ...]
    actors: tuple[HostActor, ...]
    http_routes: tuple[HostHTTPRoute, ...]
    limits: HostLimits
    configuration_root: Path
    file_digest: str
    test_routes: tuple[HostTestRoute, ...] = ()
    test_runtime: str | None = None

    @classmethod
    def from_dict(
        cls, value: Any, *, configuration_root: Path, file_digest: str = ""
    ) -> ToolHostProfile:
        row = _shape(
            value,
            {
                "schema_version",
                "profile_id",
                "tenant_id",
                "swarm_id",
                "task_id",
                "workspace",
                "files",
                "actors",
                "http_routes",
                "limits",
            },
            "profile",
            optional={"test_routes", "test_runtime"},
        )
        if row["schema_version"] != PROFILE_VERSION:
            raise ValueError("unsupported host profile schema")
        if validate_named_schema("swarm_tool_host_profile", row):
            raise ValueError("invalid managed host profile schema")
        root = _absolute(str(configuration_root), "configuration root")
        workspace = _absolute(row["workspace"], "workspace")
        if type(row["files"]) is not list or not 1 <= len(row["files"]) <= 64:
            raise ValueError("invalid host file inventory")
        if type(row["actors"]) is not list or not 1 <= len(row["actors"]) <= 16:
            raise ValueError("invalid host actor inventory")
        if type(row["http_routes"]) is not list or len(row["http_routes"]) > 16:
            raise ValueError("invalid host HTTP route inventory")
        files = tuple(HostFile.parse(item) for item in row["files"])
        actors = tuple(HostActor.parse(item) for item in row["actors"])
        routes = tuple(HostHTTPRoute.parse(item) for item in row["http_routes"])
        selected_tests = row.get("test_routes", [])
        if type(selected_tests) is not list or len(selected_tests) > 16:
            raise ValueError("invalid fixed host test inventory")
        tests = tuple(HostTestRoute.parse(item) for item in selected_tests)
        runtime = row.get("test_runtime")
        if (tests and runtime != "state/test-runtime") or (not tests and runtime is not None):
            raise ValueError("fixed host tests require their dedicated initialized runtime")
        names = {item.name for item in files}
        principals = {item.agent_id for item in actors}
        route_ids = {item.route_id for item in routes}
        test_ids = {item.test_id for item in tests}
        if (
            len(names) != len(files)
            or len(principals) != len(actors)
            or len(route_ids) != len(routes)
            or len(test_ids) != len(tests)
        ):
            raise ValueError("duplicate host profile identity")
        if any(
            not set((*actor.read_files, *actor.write_files)) <= names
            or not set(actor.http_routes) <= route_ids
            or not set(actor.peers) <= principals
            or not set(actor.test_ids) <= test_ids
            for actor in actors
        ):
            raise ValueError("host actor references an unconfigured resource")
        if any(
            selector.split("::", 1)[0] not in names
            for route in tests
            for selector in route.selectors
        ):
            raise ValueError("fixed test selector references an unconfigured managed file")
        if (
            type(file_digest) is not str
            or file_digest
            and re.fullmatch("[a-f0-9]{64}", file_digest) is None
        ):
            raise ValueError("invalid host profile file digest")
        return cls(
            _identifier(row["profile_id"], "profile_id"),
            _identifier(row["tenant_id"], "tenant_id"),
            _identifier(row["swarm_id"], "swarm_id"),
            _identifier(row["task_id"], "task_id"),
            workspace,
            files,
            actors,
            routes,
            HostLimits.parse(row["limits"]),
            root,
            file_digest,
            tests,
            runtime,
        )

    @property
    def digest(self) -> str:
        return digest(self.as_dict())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROFILE_VERSION,
            "profile_id": self.profile_id,
            "tenant_id": self.tenant_id,
            "swarm_id": self.swarm_id,
            "task_id": self.task_id,
            "workspace": str(self.workspace),
            "files": [{"name": item.name, "label": item.label} for item in self.files],
            "actors": [
                {
                    "agent_id": item.agent_id,
                    "read_files": list(item.read_files),
                    "write_files": list(item.write_files),
                    "http_routes": list(item.http_routes),
                    "peers": list(item.peers),
                    **({"test_ids": list(item.test_ids)} if item.test_ids else {}),
                }
                for item in self.actors
            ],
            "http_routes": [
                {
                    "route_id": item.route_id,
                    "url": item.url,
                    "addresses": list(item.addresses),
                    "allow_private_network": item.allow_private_network,
                    "allow_http": item.allow_http,
                    "response_limit_bytes": item.response_limit_bytes,
                    "response_label": item.response_label,
                    "credential_file": item.credential_file,
                    "ca_file": item.ca_file,
                }
                for item in self.http_routes
            ],
            "limits": {
                "requests": self.limits.requests,
                "output_bytes": self.limits.output_bytes,
                "concurrency": self.limits.concurrency,
                "lifetime_seconds": self.limits.lifetime_seconds,
            },
            **(
                {
                    "test_routes": [
                        {"test_id": item.test_id, "selectors": list(item.selectors)}
                        for item in self.test_routes
                    ],
                    "test_runtime": self.test_runtime,
                }
                if self.test_routes
                else {}
            ),
        }

    def actor(self, agent_id: str) -> HostActor:
        return (
            next(
                (actor for actor in self.actors if actor.agent_id == agent_id),
                None,
            )
            or _missing_actor()
        )

    def require_unchanged(self) -> None:
        content = read_scoped_file(
            self.configuration_root, "profile.json", maximum=65536, private=True
        )
        if not self.file_digest or hashlib.sha256(content).hexdigest() != self.file_digest:
            raise ValueError("host profile changed; current authority is fenced")


def _missing_actor() -> HostActor:
    raise ValueError("host actor is not configured")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate host profile key")
        value[key] = item
    return value


def load_host_profile(directory: Path) -> ToolHostProfile:
    """Inspect one explicitly selected private profile; start no execution."""
    root = _absolute(str(directory), "configuration root")
    raw = read_scoped_file(root, "profile.json", maximum=65536, private=True)
    try:
        content = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite host value")),
        )
    except (UnicodeError, RecursionError):
        raise ValueError("invalid bounded UTF-8 host profile") from None
    return ToolHostProfile.from_dict(
        content, configuration_root=root, file_digest=hashlib.sha256(raw).hexdigest()
    )


def check_private_directory(path: Path, *, private_leaf: bool = True) -> None:
    """Validate actual ownership/links before live host startup."""
    if not path.is_absolute():
        raise ValueError("private host directory must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("host directory is linked or is not a directory")
        if getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("host directory reparse point is unsupported")
        if os.name == "posix" and (
            info.st_uid not in {0, os.geteuid()}
            or info.st_mode & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise ValueError("host directory has an untrusted mutable ancestor")
    info = path.lstat()
    if (
        private_leaf
        and os.name == "posix"
        and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077)
    ):
        raise ValueError("host directory requires private owner permissions")


__all__ = [
    "HostActor",
    "HostFile",
    "HostHTTPRoute",
    "HostLimits",
    "HostTestRoute",
    "ToolHostProfile",
    "check_private_directory",
    "load_host_profile",
]
