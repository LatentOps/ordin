from __future__ import annotations

from . import register
from ._domain import flags, positionals
from .base import Invocation, SemanticAnalysis, evidence, flag_present, unique_evidence


SSH_VALUE_OPTIONS = {
    "-b",
    "-c",
    "-D",
    "-E",
    "-e",
    "-F",
    "-I",
    "-i",
    "-J",
    "-L",
    "-l",
    "-m",
    "-O",
    "-o",
    "-p",
    "-P",
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}


def _remote_operand(token: str) -> bool:
    if token.startswith(("ssh://", "rsync://", "scp://")):
        return True
    if ":" not in token:
        return False
    head, _, _ = token.partition(":")
    return bool(head) and "/" not in head and head not in {".", ".."}


@register("ssh", pack="remote")
def analyze_ssh(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, SSH_VALUE_OPTIONS)
    host = args[0] if args else None
    target = f"remote:{host or '*'}"
    findings = []
    if host:
        findings.append(evidence("network.connect", "ssh connection", target))
    if len(args) > 1:
        findings.append(evidence("remote.execute", "ssh remote command", target))
    return SemanticAnalysis(
        command="ssh",
        subcommand=None,
        flags=flags(invocation.args),
        targets=args,
        evidence=unique_evidence(findings),
        analyzer="ssh",
        notes=() if host else ("ssh host not identified",),
    )


def _analyze_transfer(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, SSH_VALUE_OPTIONS)
    target = "remote:file-transfer"
    findings = []
    if any(_remote_operand(item) for item in args):
        findings.append(
            evidence("network.connect", f"{invocation.executable} remote transfer", target)
        )
    if len(args) >= 2:
        source_remote = _remote_operand(args[-2])
        destination_remote = _remote_operand(args[-1])
        if source_remote and not destination_remote:
            findings.append(
                evidence("network.download", f"{invocation.executable} download", target)
            )
        if destination_remote and not source_remote:
            findings.append(evidence("network.upload", f"{invocation.executable} upload", target))
    if invocation.executable == "rsync" and flag_present(
        invocation.args,
        "--delete",
        "--delete-before",
        "--delete-during",
        "--delete-after",
    ):
        findings.append(
            evidence(
                "filesystem.delete", "rsync delete synchronization", args[-1] if args else None
            )
        )
    return SemanticAnalysis(
        command=invocation.executable,
        subcommand=None,
        flags=flags(invocation.args),
        targets=args,
        evidence=unique_evidence(findings),
        analyzer=invocation.executable,
    )


register("scp", pack="remote")(_analyze_transfer)
register("rsync", pack="remote")(_analyze_transfer)
