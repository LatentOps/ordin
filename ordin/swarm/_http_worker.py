"""Closed exact GET worker; credentials and endpoint replies stay private."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _owned_http_wire import request_bytes, request_tag, read_response
from _owned_isolation import isolate
from _owned_protocol import HTTP_PROTOCOL, wire


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate HTTP control field")
        value[key] = item
    return value


def main():
    connection = None
    try:
        raw = sys.stdin.buffer.read(1048577)
        if not 1 <= len(raw) <= 1048576:
            raise ValueError("bounded private HTTP control frame required")
        packet = json.loads(raw, object_pairs_hook=unique)
        fields = {
            "protocol",
            "request_digest",
            "nonce",
            "action_digest",
            "contract_digest",
            "policy_digest",
            "resource_descriptor",
            "uid",
            "gid",
            "memory_bytes",
            "cpu_seconds",
            "file_size_bound",
            "filter_digest",
            "url",
            "host",
            "port",
            "address",
            "headers",
            "max_response_bytes",
            "tls",
            "ca_pem",
            "ca_digest",
            "private_key",
            "credential",
            "request_tag",
            "timeout_ms",
        }
        if type(packet) is not dict or set(packet) != fields or packet["protocol"] != HTTP_PROTOCOL:
            raise ValueError("exact HTTP control frame required")
        public = {
            key: value
            for key, value in packet.items()
            if key not in {"request_digest", "private_key", "credential"}
        }
        if packet["request_digest"] != hashlib.sha256(wire(public)).hexdigest():
            raise ValueError("HTTP control binding differs")
        for key in (
            "nonce",
            "action_digest",
            "contract_digest",
            "policy_digest",
            "request_digest",
            "request_tag",
            "filter_digest",
        ):
            if (
                type(packet[key]) is not str
                or len(packet[key]) != 64
                or any(char not in "0123456789abcdef" for char in packet[key])
            ):
                raise ValueError("invalid HTTP control digest")
        private_key = base64.b64decode(packet["private_key"], validate=True)
        credential = (
            None
            if packet["credential"] is None
            else base64.b64decode(packet["credential"], validate=True)
        )
        if (
            len(private_key) != 32
            or type(packet["tls"]) is not bool
            or type(packet["timeout_ms"]) is not int
            or not 1000 <= packet["timeout_ms"] <= 10000
        ):
            raise ValueError("HTTP private binding invalid")
        request = request_bytes(packet["url"], packet["headers"], credential)
        parsed = urlsplit(packet["url"])
        if (
            parsed.hostname != packet["host"]
            or (parsed.port or (443 if parsed.scheme == "https" else 80)) != packet["port"]
            or (parsed.scheme == "https") is not packet["tls"]
        ):
            raise ValueError("HTTP SNI/endpoint differs from exact URL")
        if not hmac.compare_digest(request_tag(private_key, request), packet["request_tag"]):
            raise ValueError("HTTP exact wire request differs")
        descriptor = packet["resource_descriptor"]
        if type(descriptor) is not int or not 3 <= descriptor <= 255:
            raise ValueError("HTTP original socket descriptor required")
        if descriptor != 3:
            os.dup2(descriptor, 3, inheritable=False)
            os.close(descriptor)
        packet["resource_descriptor"] = 3
        connection = socket.socket(fileno=3)
        connection.settimeout(packet["timeout_ms"] / 1000)
        peer = connection.getpeername()
        peer_address, peer_port = str(ipaddress.ip_address(peer[0])), peer[1]
        if peer_address != packet["address"] or peer_port != packet["port"]:
            raise ValueError("HTTP preconnected destination differs")
        if packet["tls"]:
            if type(packet["ca_pem"]) is not str or not 1 <= len(packet["ca_pem"]) <= 524288:
                raise ValueError("bounded pinned CA material required")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cadata=packet["ca_pem"])
            authority = hashlib.sha256(
                wire(
                    sorted(
                        hashlib.sha256(item).hexdigest()
                        for item in context.get_ca_certs(binary_form=True)
                    )
                )
            ).hexdigest()
            if authority != packet["ca_digest"]:
                raise ValueError("TLS trust material differs")
            connection = context.wrap_socket(
                connection, server_hostname=packet["host"], do_handshake_on_connect=False
            )
        elif (
            credential is not None
            or packet["ca_pem"] is not None
            or packet["ca_digest"] is not None
        ):
            raise ValueError("HTTP cannot carry credentials or TLS material")
        isolation = isolate(packet, "http")
        if packet["tls"]:
            if not isinstance(connection, ssl.SSLSocket):
                raise ValueError("original strict TLS socket required")
            connection.do_handshake()
            if not connection.getpeercert() or connection.version() not in {"TLSv1.2", "TLSv1.3"}:
                raise ValueError("strict TLS verification unavailable")
        connection.sendall(request)
        body = read_response(connection, packet["max_response_bytes"], require_length=packet["tls"])
        # The original peer was checked before TLS or request bytes. The closed
        # profile denies connect/socket/descriptor replacement, so it cannot
        # change. TLS teardown may make a later getpeername return ENOTCONN even
        # after an authenticated complete response; retain the earlier proof.
        value = b'{"completed":true,"credentialed":true}' if credential is not None else body
        response = {
            key: packet[key]
            for key in (
                "protocol",
                "request_digest",
                "nonce",
                "action_digest",
                "contract_digest",
                "policy_digest",
            )
        }
        response.update(
            status="completed",
            request_tag=packet["request_tag"],
            address=peer_address,
            port=peer_port,
            tls_verified=packet["tls"],
            delivery="fixed_completion_receipt" if credential is not None else "bounded_body",
            value=base64.b64encode(value).decode("ascii"),
            isolation=isolation,
        )
        frame = wire(response)
        if len(frame) > packet["file_size_bound"]:
            raise ValueError("HTTP output frame bound exceeded")
        os.write(1, frame)
        return 0
    except Exception:
        os.write(1, wire({"protocol": HTTP_PROTOCOL, "status": "unknown"}))
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
