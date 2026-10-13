"""Explicit deterministic REST classification; no transport or authority is issued."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import re

from ._request_commitment import request_commitment
from ._runtime_json import digest

REST_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
READ_METHODS = frozenset(("GET", "HEAD", "OPTIONS"))
HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
UNSUPPORTED_HEADERS = frozenset(
    (
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "authorization",
        "proxy-authorization",
        "cookie",
    )
)


@dataclass(frozen=True)
class RestSemantics:
    """Host opt-in to bounded literal REST actions; this does not approve them."""

    methods: tuple[str, ...] = REST_METHODS

    def __post_init__(self):
        if (
            not isinstance(self.methods, tuple)
            or not self.methods
            or any(method not in REST_METHODS for method in self.methods)
            or len(set(self.methods)) != len(self.methods)
        ):
            raise ValueError("REST semantic selection must name supported exact methods")

    def as_dict(self):
        return {
            "schema_version": "ordin.assurance_rest_semantics.v1",
            "methods": list(self.methods),
        }

    @property
    def digest(self):
        return digest(self.as_dict())


def prepare_rest(parameters):
    from .runtime_requests import request_endpoint

    if (
        not isinstance(parameters, Mapping)
        or not {"url", "method"} <= set(parameters)
        or set(parameters) - {"url", "method", "headers", "body"}
    ):
        raise ValueError("rest_request_unsupported")
    url, method = parameters["url"], parameters["method"]
    endpoint = request_endpoint(url)
    if (
        endpoint is None
        or not isinstance(url, str)
        or "?" in url
        or "#" in url
        or len(url.encode("utf-8")) > 4096
        or method not in REST_METHODS
    ):
        raise ValueError("rest_request_unsupported")
    headers = parameters.get("headers", {})
    if not isinstance(headers, Mapping) or len(headers) > 128:
        raise ValueError("rest_request_unsupported")
    normalized = {}
    for name, value in headers.items():
        if (
            not isinstance(name, str)
            or HEADER.fullmatch(name) is None
            or name.lower() in normalized
            or name.lower() in UNSUPPORTED_HEADERS
            or name.lower().startswith("proxy-")
            or not isinstance(value, str)
            or len(value.encode("utf-8")) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("rest_request_unsupported")
        normalized[name.lower()] = value
    if (
        "body" in parameters
        and normalized.get("content-type", "application/json") != "application/json"
    ):
        raise ValueError("rest_request_unsupported")
    # Headers/body are exact typed JSON input. Omitted body differs from null.
    material = {"method": method, "url": url, "headers": normalized}
    if "body" in parameters:
        material["body"] = parameters["body"]
    commitment = request_commitment(material)
    reading = method in READ_METHODS and "body" not in parameters
    return endpoint, method, commitment, reading
