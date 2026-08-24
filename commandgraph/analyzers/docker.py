from __future__ import annotations

from . import register
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    unique_evidence,
)


GLOBAL_VALUE_OPTIONS = {
    "--config",
    "-c",
    "--context",
    "-H",
    "--host",
    "-l",
    "--log-level",
}
READ_COMMANDS = {
    "ps",
    "images",
    "inspect",
    "info",
    "version",
    "stats",
    "logs",
    "top",
    "port",
}
CREATE_COMMANDS = {
    "run",
    "create",
    "start",
    "restart",
    "unpause",
}
DELETE_COMMANDS = {
    "rm",
    "rmi",
}
PRUNE_PAIRS = {
    ("system", "prune"),
    ("image", "prune"),
    ("container", "prune"),
    ("volume", "prune"),
    ("network", "prune"),
    ("builder", "prune"),
}
DELETE_PAIRS = {
    ("container", "rm"),
    ("image", "rm"),
    ("volume", "rm"),
    ("network", "rm"),
}


def _split_docker_args(args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("-"):
            break
        key = token.split("=", 1)[0]
        if key in GLOBAL_VALUE_OPTIONS and "=" not in token:
            index += 2
        else:
            index += 1
    if index >= len(args):
        return None, ()
    return args[index], args[index + 1:]


def _targets(args: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(token for token in args if not token.startswith("-"))


@register("docker", pack="docker")
def analyze_docker(invocation: Invocation) -> SemanticAnalysis:
    subcommand, args = _split_docker_args(invocation.args)
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _targets(args)
    findings = []

    pair = (subcommand, args[0] if args else None)
    if subcommand in READ_COMMANDS:
        findings.append(evidence("container.read", f"docker {subcommand}"))

    elif subcommand in CREATE_COMMANDS:
        findings.append(evidence("container.create", f"docker {subcommand}"))
        if flag_present(args, "--privileged"):
            findings.append(evidence("privilege.escalate", "docker --privileged"))

    elif subcommand in DELETE_COMMANDS or pair in DELETE_PAIRS:
        findings.append(evidence("container.delete", f"docker {subcommand}"))
        if flag_present(args, "-f", "--force", short_chars="f"):
            findings.append(evidence("confirmation.bypass", "docker force removal"))

    elif pair in PRUNE_PAIRS:
        findings.append(evidence("container.prune", f"docker {subcommand} prune"))
        if flag_present(args, "-f", "--force", short_chars="f"):
            findings.append(evidence("confirmation.bypass", "docker prune force flag"))

    elif subcommand in {"exec", "build"}:
        findings.append(evidence("code.execute", f"docker {subcommand}"))

    elif subcommand == "pull":
        findings.append(evidence("network.download", "docker pull"))

    elif subcommand == "push":
        findings.append(evidence("network.upload", "docker push"))

    elif subcommand == "compose":
        compose_subcommand = args[0] if args else None
        if compose_subcommand in {"ps", "logs", "config", "images"}:
            findings.append(evidence("container.read", f"docker compose {compose_subcommand}"))
        elif compose_subcommand in {"up", "start", "restart"}:
            findings.append(
                evidence("container.create", f"docker compose {compose_subcommand}")
            )
        elif compose_subcommand in {"down", "rm"}:
            findings.append(
                evidence("container.delete", f"docker compose {compose_subcommand}")
            )
        elif compose_subcommand in {"exec", "run"}:
            findings.append(evidence("code.execute", f"docker compose {compose_subcommand}"))

    return SemanticAnalysis(
        command="docker",
        subcommand=subcommand,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="docker",
        notes=() if subcommand else ("docker subcommand not identified",),
    )
