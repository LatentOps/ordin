"""Explicit local private PKI bootstrap; never install a machine trust root."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys

from ordin.assurance._files import read_scoped_file

from .host_profiles import ToolHostProfile, check_private_directory


def _new_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _openssl(executable: str, arguments: list[str], directory: Path) -> None:
    subprocess.run(
        [executable, *arguments],
        cwd=directory,
        check=True,
        timeout=20,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "SystemRoot", "WINDIR", "TMP", "TEMP", "TMPDIR"}
        },
        **({"umask": 0o077} if os.name == "posix" else {}),
    )


def initialize_private_profile(
    directory: Path, document: dict, *, openssl_executable: Path | None = None
) -> str:
    """Create a NEW operator-owned installation, with fresh private keys.

    The data-only document has already been chosen by the operator. Neither
    certificate issuance nor profile creation approves an agent tool action.
    Failed initialization leaves its private partial directory for inspection.
    """
    if sys.platform != "linux":
        raise ValueError("managed host initialization requires supported Linux ownership")
    if not directory.is_absolute() or ".." in directory.parts or directory.exists():
        raise ValueError("host installation requires a new explicit absolute directory")
    selected = openssl_executable or Path("/usr/bin/openssl")
    if not selected.is_absolute():
        raise ValueError("OpenSSL must be an explicitly selected absolute executable")
    try:
        binary = selected.resolve(strict=True)
        information = binary.stat()
    except OSError:
        raise ValueError("OpenSSL is required for explicit private host initialization")
    if (
        not stat.S_ISREG(information.st_mode)
        or not os.access(binary, os.X_OK)
        or information.st_uid not in {0, os.geteuid()}
        or information.st_mode & 0o022
    ):
        raise ValueError("OpenSSL executable ownership or permissions are unsupported")
    executable = str(binary)
    profile = ToolHostProfile.from_dict(document, configuration_root=directory)
    # A managed host never creates or changes permissions on an existing user workspace.
    if profile.workspace != directory / "workspace":
        raise ValueError("new host workspace must belong to its new installation")
    directory.mkdir(mode=0o700)
    check_private_directory(directory)
    pki = directory / "pki"
    pki.mkdir(mode=0o700)
    (directory / "state").mkdir(mode=0o700)
    profile.workspace.mkdir(mode=0o700)
    _openssl(
        executable,
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Ordin-private-task-CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        pki,
    )
    names = (
        "server",
        "broker",
        "authority-root",
        "operator",
        *(actor.agent_id for actor in profile.actors),
    )
    for name in names:
        _openssl(
            executable,
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                name + "-key.pem",
                "-out",
                name + ".csr",
                "-subj",
                "/CN=" + ("localhost" if name == "server" else name),
            ],
            pki,
        )
        extension = (
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            + "extendedKeyUsage="
            + ("serverAuth" if name == "server" else "clientAuth")
            + "\n"
            + ("subjectAltName=DNS:localhost\n" if name == "server" else "")
        )
        _new_file(pki / (name + ".ext"), extension.encode("ascii"))
        _openssl(
            executable,
            [
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca-key.pem",
                "-CAcreateserial",
                "-out",
                name + ".pem",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                name + ".ext",
            ],
            pki,
        )
        (pki / (name + ".csr")).unlink()
        (pki / (name + ".ext")).unlink()
    for item in pki.iterdir():
        info = item.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ValueError("private host PKI output changed")
        item.chmod(0o600)
    raw = (
        json.dumps(
            profile.as_dict(), sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        + b"\n"
    )
    if len(raw) > 65536:
        raise ValueError("host profile exceeds its encoded limit")
    _new_file(directory / "profile.json", raw)
    return hashlib.sha256(raw).hexdigest()


class PrivateHostPKI:
    """Original live SSL contexts over one explicitly selected private install."""

    def __init__(self, profile: ToolHostProfile) -> None:
        if type(profile) is not ToolHostProfile:
            raise ValueError("typed private host profile required")
        check_private_directory(profile.configuration_root)
        self.root = profile.configuration_root / "pki"
        check_private_directory(self.root)
        self.names = frozenset(
            (
                "server",
                "broker",
                "authority-root",
                "operator",
                *(actor.agent_id for actor in profile.actors),
            )
        )
        self._snapshots = {
            name: hashlib.sha256(
                read_scoped_file(self.root, name, maximum=16384, private=True)
            ).hexdigest()
            for name in (
                "ca.pem",
                *(part for actor in self.names for part in (actor + ".pem", actor + "-key.pem")),
            )
        }
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.server_context.verify_mode = ssl.CERT_REQUIRED
        self.server_context.load_verify_locations(cafile=str(self.root / "ca.pem"))
        self.server_context.load_cert_chain(
            str(self.root / "server.pem"), str(self.root / "server-key.pem")
        )
        self.require_unchanged()

    def require_unchanged(self) -> None:
        for name, expected in self._snapshots.items():
            actual = read_scoped_file(self.root, name, maximum=16384, private=True)
            if hashlib.sha256(actual).hexdigest() != expected:
                raise ValueError("private host TLS material changed; restart and reenroll")

    def fingerprint(self, name: str) -> str:
        if name not in self.names or name == "server":
            raise ValueError("unconfigured private TLS workload")
        self.require_unchanged()
        raw = read_scoped_file(self.root, name + ".pem", maximum=16384, private=True)
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))).hexdigest()

    @contextmanager
    def pair(self, name: str):
        if name not in self.names or name == "server":
            raise ValueError("unconfigured private TLS workload")
        self.require_unchanged()
        with ExitStack() as stack:
            left, right = socket.socketpair()
            stack.callback(left.close)
            stack.callback(right.close)
            left.settimeout(5)
            right.settimeout(5)
            client_context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=str(self.root / "ca.pem")
            )
            client_context.minimum_version = ssl.TLSVersion.TLSv1_2
            client_context.load_cert_chain(
                str(self.root / (name + ".pem")), str(self.root / (name + "-key.pem"))
            )
            self.require_unchanged()
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.server_context.wrap_socket, left, server_side=True)
                client = client_context.wrap_socket(right, server_hostname="localhost")
                stack.callback(client.close)
                server = pending.result(timeout=5)
                stack.callback(server.close)
            yield server, client


__all__ = ["PrivateHostPKI", "initialize_private_profile"]
