from __future__ import annotations

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


VALUE_OPTIONS = {"--hostname", "--repo", "-R"}
READ_OPERATIONS = {"checks", "diff", "list", "status", "view"}
WRITE_OPERATIONS = {"close", "create", "disable", "edit", "enable", "merge", "reopen"}


@register("gh", pack="github")
def analyze_gh(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    group = args[0].lower() if args else None
    operation = args[1].lower() if len(args) > 1 else None
    combined = f"{group} {operation}" if group and operation else group
    target_name = args[2] if len(args) > 2 else "*"
    target = resource("github", group or "*", target_name)
    findings = []

    if group == "api":
        endpoint = args[1] if len(args) > 1 else "*"
        method = (option_value(invocation.args, "--method", short_names=("-X",)) or "GET").upper()
        target = resource("github", "api", endpoint)
        findings.append(evidence("network.connect", "gh api", target))
        if method == "DELETE":
            findings.append(evidence("infrastructure.delete", "gh api DELETE", target))
        elif method in {"GET", "HEAD"}:
            findings.append(evidence("infrastructure.read", f"gh api {method}", target))
        else:
            findings.append(evidence("infrastructure.write", f"gh api {method}", target))
        if flag_present(invocation.args, "--input", "--field", "--raw-field", "-f", "-F"):
            findings.append(evidence("network.upload", "gh api request data", target))
    elif combined == "auth token":
        findings.append(evidence("secret.read", "gh auth token", "github:credential"))
    elif group == "auth" and operation in {"login", "logout", "refresh"}:
        findings.append(
            evidence("identity.permission_change", f"gh {combined}", "github:credential")
        )
    elif group == "secret":
        if operation == "list":
            findings.append(evidence("infrastructure.read", f"gh {combined}", target))
        elif operation == "set":
            findings.append(evidence("secret.write", f"gh {combined}", target))
        elif operation in {"delete", "remove"}:
            findings.append(evidence("infrastructure.delete", f"gh {combined}", target))
    elif combined in {"repo clone", "release download", "run download"}:
        findings.append(evidence("network.download", f"gh {combined}", target))
    elif combined == "release upload":
        findings.append(evidence("network.upload", f"gh {combined}", target))
    elif operation in {"delete", "remove"}:
        findings.append(evidence("infrastructure.delete", f"gh {combined}", target))
    elif operation in WRITE_OPERATIONS:
        findings.append(evidence("infrastructure.write", f"gh {combined}", target))
    elif operation in READ_OPERATIONS or combined in {"auth status", "repo view"}:
        findings.append(evidence("infrastructure.read", f"gh {combined}", target))

    if findings and not any(item.effect == "network.connect" for item in findings):
        findings.append(evidence("network.connect", "gh remote operation", target))
    return SemanticAnalysis(
        command="gh",
        subcommand=combined,
        flags=flags(invocation.args),
        targets=args[2:],
        evidence=unique_evidence(findings),
        analyzer="gh",
    )
