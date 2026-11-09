"""Explicit bounded loopback mTLS service and standard MCP stdio client bridge."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import stat
import time
from threading import BoundedSemaphore, RLock, Thread, current_thread
from uuid import uuid4

from ordin.assurance._files import read_scoped_file

from .host_pki import _new_file
from .host_profiles import check_private_directory
from .host_protocol import MAX_FRAME_BYTES, MCPHostSession, decode_frame, encode_frame, serve_stdio
from .host_runtime import ManagedToolHost
from .host_authority import _HostCleanupIncomplete


CLIENT_VERSION = "ordin.swarm_tool_host_client.v1"


def _replace_private(path: Path, content: bytes) -> None:
    check_private_directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or os.name == "posix"
            and (info.st_uid != os.geteuid() or info.st_mode & 0o077)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("managed client output is linked or not private")
    temporary = path.parent / (".new-" + uuid4().hex)
    _new_file(temporary, content)
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class ManagedHostServer:
    """One shared authority, finite connections, explicit loopback listener only."""

    def __init__(self, host: ManagedToolHost, *, operator: object, port=9443):
        if type(host) is not ManagedToolHost or operator is not host._operator:
            raise ValueError("original managed host service operator required")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid managed host port")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.set_inheritable(False)
            listener.bind(("127.0.0.1", port))
            listener.listen(16)
            listener.settimeout(0.5)
        except BaseException:
            listener.close()
            raise
        self.host, self._operator, self.listener = host, operator, listener
        self.port = listener.getsockname()[1]
        self._slots = BoundedSemaphore(32)
        self._lock = RLock()
        self._close_lock = RLock()
        self._cleanup_complete = False
        self._sockets: set[socket.socket] = set()
        self._threads: set[Thread] = set()
        try:
            self._publish_clients()
        except BaseException:
            listener.close()
            raise

    def _publish_clients(self) -> None:
        root = self.host.profile.configuration_root
        parent = root / "clients"
        if not parent.exists():
            parent.mkdir(mode=0o700)
        check_private_directory(parent)
        self.host._authority.pki.require_unchanged()
        for name in (*(actor.agent_id for actor in self.host.profile.actors), "operator"):
            directory = parent / name
            if not directory.exists():
                directory.mkdir(mode=0o700)
            check_private_directory(directory)
            for destination, source in (
                ("ca.pem", "ca.pem"),
                ("cert.pem", name + "/cert.pem"),
                ("key.pem", name + "/key.pem"),
            ):
                raw = read_scoped_file(root / "pki", source, maximum=16384, private=True)
                _replace_private(directory / destination, raw)
            configuration = {
                "schema_version": CLIENT_VERSION,
                "host": "127.0.0.1",
                "port": self.port,
                "server_hostname": "localhost",
                "profile_digest": self.host.profile.digest,
                "actor_id": name,
            }
            _replace_private(
                directory / "client.json",
                json.dumps(configuration, sort_keys=True).encode("utf-8") + b"\n",
            )
        _replace_private(
            root / "state" / "endpoint.json",
            json.dumps(
                {
                    "schema_version": "ordin.swarm_tool_host_endpoint.v1",
                    "host": "127.0.0.1",
                    "port": self.port,
                    "profile_digest": self.host.profile.digest,
                    "incarnation": self.host._authority.incarnation,
                    "online_evidence": False,
                },
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
        )

    def _connection(self, raw: socket.socket) -> None:
        connection = None
        session = None
        client = None
        try:
            raw.settimeout(5)
            connection = self.host._authority.pki.server_context.wrap_socket(raw, server_side=True)
            with self._lock:
                self._sockets.discard(raw)
                self._sockets.add(connection)
            with self.host._authority.control_phase():
                remaining = self.host._authority.expires_at - self.host._authority.clock()
                if remaining <= 0:
                    return
                connection.settimeout(min(600, max(1, remaining)))
                client = self.host.bind_connection(connection, operator=self._operator)
                session = MCPHostSession(self.host, client)
            with connection.makefile("rb") as incoming, connection.makefile("wb") as outgoing:
                serve_stdio(session, incoming, outgoing)
        except (ValueError, OSError, RuntimeError, ssl.SSLError):
            # No raw request, payload, credential or transport exception is logged.
            pass
        finally:
            if session is not None:
                session.close()
            elif client is not None:
                self.host.close_client(client)
            if connection is not None:
                connection.close()
            raw.close()
            with self._lock:
                self._sockets.discard(raw)
                if connection is not None:
                    self._sockets.discard(connection)
            self._slots.release()

    def run(self) -> int:
        next_maintenance = 0.0
        try:

            def stop_on_request():
                self.host.shutdown_requested.wait()
                try:
                    self.host.request_shutdown(operator=self._operator)
                except (ValueError, OSError, RuntimeError):
                    pass  # close() retains custody until actual cleanup succeeds.

            watcher = Thread(target=stop_on_request, name="ordin-managed-host-stop", daemon=True)
            with self._lock:
                self._threads.add(watcher)
            try:
                watcher.start()
            except BaseException:
                with self._lock:
                    self._threads.discard(watcher)
                raise
            while not self.host.shutdown_requested.is_set():
                # Scheduling uses monotonic time only; authority timestamps
                # remain original CoordinatorClock samples inside the phase.
                now = time.monotonic()
                if now >= next_maintenance:
                    self.host.maintenance()
                    next_maintenance = now + 5
                try:
                    raw, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.host.shutdown_requested.is_set():
                        break
                    raise
                if not self._slots.acquire(blocking=False):
                    raw.close()
                    continue
                with self._lock:
                    self._sockets.add(raw)
                    self._threads = {thread for thread in self._threads if thread.is_alive()}
                thread = Thread(target=self._connection, args=(raw,), daemon=True)
                with self._lock:
                    self._threads.add(thread)
                try:
                    thread.start()
                except BaseException:
                    with self._lock:
                        self._sockets.discard(raw)
                        self._threads.discard(thread)
                    self._slots.release()
                    raw.close()
                    raise
            return 0
        finally:
            self.close()

    def close(self) -> None:
        with self._close_lock:
            if self._cleanup_complete:
                return
            self.host.shutdown_requested.set()
            error = None
            try:
                self.host.request_shutdown(operator=self._operator)
            except BaseException as failure:
                error = failure
            try:
                self.listener.close()
            except BaseException as failure:
                error = error or failure
            with self._lock:
                connections = tuple(self._sockets)
                threads = tuple(self._threads)
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except (ValueError, OSError):
                    pass
                try:
                    connection.close()
                except BaseException as failure:
                    error = error or failure
            deadline = time.monotonic() + 5
            for thread in threads:
                if thread is not current_thread():
                    thread.join(timeout=max(0, deadline - time.monotonic()))
            try:
                self.host.close()
            except BaseException as failure:
                error = error or failure
            if error is not None:
                raise _HostCleanupIncomplete(self) from error
            if any(thread.is_alive() for thread in threads):
                raise _HostCleanupIncomplete(self)
            self._cleanup_complete = True


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate managed client field")
        result[key] = value
    return result


def connect(directory: Path) -> ssl.SSLSocket:
    """Connect only when explicitly called with one private role bundle."""
    if not directory.is_absolute():
        raise ValueError("explicit absolute managed client directory required")
    check_private_directory(directory)
    raw = read_scoped_file(directory, "client.json", maximum=4096, private=True)
    configuration = json.loads(raw, object_pairs_hook=_unique)
    if (
        type(configuration) is not dict
        or set(configuration)
        != {"schema_version", "host", "port", "server_hostname", "profile_digest", "actor_id"}
        or configuration["schema_version"] != CLIENT_VERSION
        or configuration["host"] != "127.0.0.1"
        or configuration["server_hostname"] != "localhost"
        or type(configuration["port"]) is not int
        or not 1 <= configuration["port"] <= 65535
        or type(configuration["profile_digest"]) is not str
        or len(configuration["profile_digest"]) != 64
        or any(c not in "0123456789abcdef" for c in configuration["profile_digest"])
        or type(configuration["actor_id"]) is not str
        or not 1 <= len(configuration["actor_id"]) <= 64
    ):
        raise ValueError("invalid bounded loopback managed client configuration")
    before = {
        name: read_scoped_file(directory, name, maximum=16384, private=True)
        for name in ("ca.pem", "cert.pem", "key.pem")
    }
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(directory / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(directory / "cert.pem"), str(directory / "key.pem"))
    for name, expected in before.items():
        if read_scoped_file(directory, name, maximum=16384, private=True) != expected:
            raise ValueError("managed client TLS material changed")
    connection = socket.create_connection((configuration["host"], configuration["port"]), timeout=5)
    try:
        secure = context.wrap_socket(connection, server_hostname="localhost")
        secure.settimeout(30)
        return secure
    except BaseException:
        connection.close()
        raise


def bridge_stdio(directory: Path, incoming, outgoing) -> int:
    """Sequential MCP stdio, no reconnect/retry or identity fields on the wire."""
    with connect(directory) as connection, connection.makefile("rb") as replies:
        while True:
            raw = incoming.readline(MAX_FRAME_BYTES + 1)
            if not raw:
                return 0
            if not raw.endswith(b"\n") or len(raw) > MAX_FRAME_BYTES:
                raise ValueError("managed client input frame exceeded its boundary")
            request = decode_frame(raw)
            connection.sendall(raw)
            if "id" not in request:
                continue
            response = replies.readline(MAX_FRAME_BYTES + 1)
            if not response or len(response) > MAX_FRAME_BYTES or not response.endswith(b"\n"):
                raise ValueError("managed response unknown; do not retry the effect")
            parsed = json.loads(response, object_pairs_hook=_unique)
            if (
                type(parsed) is not dict
                or parsed.get("jsonrpc") != "2.0"
                or type(parsed.get("id")) is not type(request["id"])
                or parsed["id"] != request["id"]
                or (("result" in parsed) == ("error" in parsed))
            ):
                raise ValueError("managed response identity changed; do not retry the effect")
            outgoing.write(response)
            outgoing.flush()


def request(connection: ssl.SSLSocket, message: dict) -> dict | None:
    """Bounded command helper for the explicit operator CLI."""
    outgoing = encode_frame(message)
    decode_frame(outgoing)
    connection.sendall(outgoing)
    if "id" not in message:
        return None
    data = bytearray()
    while len(data) <= MAX_FRAME_BYTES:
        part = connection.recv(min(4096, MAX_FRAME_BYTES + 1 - len(data)))
        if not part:
            raise ValueError("managed response unknown; do not retry the effect")
        data.extend(part)
        if b"\n" in part:
            break
    if len(data) > MAX_FRAME_BYTES or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError("managed response frame limit")
    value = json.loads(data, object_pairs_hook=_unique)
    if (
        type(value) is not dict
        or value.get("jsonrpc") != "2.0"
        or type(value.get("id")) is not type(message["id"])
        or value["id"] != message["id"]
    ):
        raise ValueError("managed response identity mismatch")
    return value


__all__ = ["ManagedHostServer", "bridge_stdio", "connect", "request"]
