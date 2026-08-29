from __future__ import annotations

import re

from . import register
from ._domain import flags, positionals, resource
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    option_value,
    unique_evidence,
)


SQL_READ = re.compile(r"^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|PRAGMA|WITH)\b", re.I)
SQL_DELETE = re.compile(r"^\s*(DROP|TRUNCATE|DELETE)\b", re.I)
SQL_PERMISSION = re.compile(
    r"^\s*(GRANT|REVOKE|CREATE\s+(USER|ROLE)|ALTER\s+(USER|ROLE)|DROP\s+(USER|ROLE))\b",
    re.I,
)
SQL_WRITE = re.compile(
    r"^\s*(INSERT|UPDATE|CREATE|ALTER|REPLACE|MERGE|UPSERT|COPY|VACUUM|REINDEX)\b",
    re.I,
)
REDIS_READ = {"EXISTS", "GET", "HGET", "HGETALL", "INFO", "KEYS", "MGET", "PING", "SCAN", "TTL"}
REDIS_DELETE = {"DEL", "FLUSHALL", "FLUSHDB", "UNLINK"}
REDIS_WRITE = {
    "EXPIRE",
    "HSET",
    "LPUSH",
    "MSET",
    "PERSIST",
    "RENAME",
    "RPUSH",
    "SADD",
    "SET",
    "ZADD",
}


def _query_and_database(invocation: Invocation) -> tuple[str | None, str]:
    executable = invocation.executable
    if executable == "psql":
        return (
            option_value(invocation.args, "--command", short_names=("-c",)),
            option_value(invocation.args, "--dbname", short_names=("-d",)) or "*",
        )
    if executable in {"mysql", "mariadb"}:
        query = option_value(invocation.args, "--execute", short_names=("-e",))
        args = positionals(
            invocation.args,
            {"--database", "--execute", "--host", "--port", "--user", "-D", "-e", "-h", "-P", "-u"},
        )
        return query, args[0] if args else "*"
    if executable == "sqlite3":
        args = positionals(invocation.args)
        return (args[1] if len(args) > 1 else None, args[0] if args else "*")
    if executable == "mongosh":
        query = option_value(invocation.args, "--eval")
        args = positionals(invocation.args, {"--eval", "--host", "--port", "--username"})
        return query, args[0] if args else "*"
    if executable == "redis-cli":
        args = positionals(
            invocation.args,
            {"--host", "--pass", "--port", "--user", "-a", "-h", "-p"},
        )
        return (" ".join(args) if args else None, "redis")
    return None, "*"


def _effect_for_query(query: str) -> str:
    if SQL_PERMISSION.search(query):
        return "identity.permission_change"
    if SQL_DELETE.search(query):
        return "database.delete"
    if SQL_READ.search(query):
        return "database.read"
    if SQL_WRITE.search(query):
        return "database.write"
    upper = query.lstrip().upper()
    if ".DROPDATABASE(" in upper or re.search(r"\.DROP\s*\(", upper):
        return "database.delete"
    command = upper.split(None, 1)[0] if upper else ""
    if command in REDIS_READ:
        return "database.read"
    if command in REDIS_DELETE:
        return "database.delete"
    if command == "ACL" and any(word in upper for word in ("SETUSER", "DELUSER")):
        return "identity.permission_change"
    if command in REDIS_WRITE:
        return "database.write"
    return "database.write"


def analyze_database(invocation: Invocation) -> SemanticAnalysis:
    query, database = _query_and_database(invocation)
    host = option_value(invocation.args, "--host", short_names=("-h",)) or "local"
    target = resource("database", invocation.executable, host, database)
    findings = []
    if invocation.executable != "sqlite3":
        findings.append(evidence("network.connect", f"{invocation.executable} connection", target))
    if query:
        effect_name = _effect_for_query(query)
        findings.append(evidence(effect_name, f"{invocation.executable} query", target))
        if effect_name == "identity.permission_change":
            findings.append(
                evidence("database.write", f"{invocation.executable} privilege query", target)
            )
    if flag_present(invocation.args, "--file", "-f"):
        findings.append(evidence("database.write", f"{invocation.executable} script file", target))
    return SemanticAnalysis(
        command=invocation.executable,
        subcommand=None,
        flags=flags(invocation.args),
        targets=(database,),
        evidence=unique_evidence(findings),
        analyzer=invocation.executable,
    )


for executable in ("psql", "mysql", "mariadb", "sqlite3", "mongosh", "redis-cli"):
    register(executable, pack="database")(analyze_database)
