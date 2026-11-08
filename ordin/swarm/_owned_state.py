"""Private managed-file CAS history; persisted metadata never restores execution authority."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from ordin._private_storage import private_database
from ordin._runtime_json import digest

from .models import counter


SCHEMA = (
    "CREATE TABLE owned_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL, names TEXT NOT NULL)",
    "CREATE TABLE owned_files (name TEXT PRIMARY KEY, data TEXT NOT NULL, checksum TEXT NOT NULL)",
)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("managed history has duplicate fields")
        result[key] = value
    return result


def _decode(raw):
    if type(raw) is not str or len(raw.encode("utf-8")) > 16384:
        raise ValueError("managed history exceeds its bound")
    value = json.loads(raw, object_pairs_hook=_unique)
    if type(value) is not dict:
        raise ValueError("managed history must be an object")
    return value


def _encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(raw.encode("utf-8")) > 16384:
        raise ValueError("managed history exceeds its bound")
    return raw


class OwnedFileState:
    """One original live owner plus durable version and unresolved-intent floors."""

    def __init__(self, path: Path, binding: str, initial: dict, *, initialize: bool):
        import fcntl

        self.path, self._binding = Path(path).absolute(), binding
        self._names = tuple(sorted(initial))
        self._lock_fd = os.open(
            self.path.with_suffix(".lock"),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(self._lock_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ValueError("managed owner lock must be private")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if initialize:
                descriptor = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
                os.close(descriptor)
                with private_database(self.path, "swarm_owned_tools", create=False) as connection:
                    for statement in SCHEMA:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO owned_meta VALUES(1,?,?)", (binding, json.dumps(self._names))
                    )
                    for name, value in initial.items():
                        connection.execute(
                            "INSERT INTO owned_files VALUES(?,?,?)",
                            (name, _encode(value), digest(value)),
                        )
            info = self.path.stat()
            self._identity = info.st_dev, info.st_ino
            with private_database(
                self.path, "swarm_owned_tools", readonly=True, create=False
            ) as connection:
                self._check(connection)
                for name in self._names:
                    self._row(connection, name)
        except BaseException:
            os.close(self._lock_fd)
            self._lock_fd = -1
            raise

    def _check(self, connection):
        if self._lock_fd < 0:
            raise ValueError("managed state owner is closed")
        info = self.path.stat()
        if (info.st_dev, info.st_ino) != self._identity:
            raise ValueError("managed history was replaced")
        actual = {
            row[0]: " ".join(row[1].split())
            for row in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        if actual != {statement.split()[2]: " ".join(statement.split()) for statement in SCHEMA}:
            raise ValueError("managed history schema changed")
        rows = connection.execute("SELECT singleton,binding,names FROM owned_meta").fetchall()
        if len(rows) != 1 or tuple(rows[0]) != (1, self._binding, json.dumps(self._names)):
            raise ValueError("managed workspace identity or enrollment changed")
        names = tuple(
            row[0] for row in connection.execute("SELECT name FROM owned_files ORDER BY name")
        )
        if names != self._names:
            raise ValueError("managed file history missing or changed")

    @staticmethod
    def _row(connection, name):
        row = connection.execute(
            "SELECT data,checksum FROM owned_files WHERE name=?", (name,)
        ).fetchone()
        if row is None:
            raise ValueError("unrepresented managed file")
        value = _decode(row[0])
        if (
            set(value) != {"version", "content_digest", "identity", "pending"}
            or digest(value) != row[1]
        ):
            raise ValueError("managed file history changed")
        counter(value["version"], "managed version")
        if (value["version"] == 0) != (value["identity"] is None) or (value["version"] == 0) != (
            value["content_digest"] is None
        ):
            raise ValueError("managed file version history incomplete")
        return value

    @staticmethod
    def _save(connection, name, value):
        connection.execute(
            "UPDATE owned_files SET data=?,checksum=? WHERE name=?",
            (_encode(value), digest(value), name),
        )

    def record(self, name):
        with private_database(
            self.path, "swarm_owned_tools", readonly=True, create=False
        ) as connection:
            self._check(connection)
            value = self._row(connection, name)
            if value["pending"] is not None:
                raise ValueError(
                    "managed write outcome unresolved; operator reconciliation required"
                )
            return value

    def begin(self, name, expected, *, nonce, action_digest, content_digest):
        with private_database(self.path, "swarm_owned_tools", create=False) as connection:
            self._check(connection)
            value = self._row(connection, name)
            if value != expected or value["pending"] is not None:
                raise ValueError("managed file CAS changed")
            value["pending"] = {
                "nonce": nonce,
                "action_digest": action_digest,
                "content_digest": content_digest,
                "version": counter(value["version"] + 1, "managed version"),
            }
            self._save(connection, name, value)

    def finish(self, name, nonce, *, identity, content_digest, completed):
        with private_database(self.path, "swarm_owned_tools", create=False) as connection:
            self._check(connection)
            value = self._row(connection, name)
            pending = value["pending"]
            if type(pending) is not dict or pending.get("nonce") != nonce:
                raise ValueError("original managed write intent unavailable")
            if completed:
                if pending["content_digest"] != content_digest:
                    raise ValueError("managed write digest differs from original intent")
                value.update(
                    version=pending["version"], identity=identity, content_digest=content_digest
                )
            elif value["identity"] != identity or value["content_digest"] != content_digest:
                raise ValueError("denied write cannot reconcile changed data")
            value["pending"] = None
            self._save(connection, name, value)
            return value

    def close(self):
        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1
