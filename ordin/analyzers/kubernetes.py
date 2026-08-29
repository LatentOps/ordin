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


VALUE_OPTIONS = {
    "--as",
    "--as-group",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kubeconfig",
    "--namespace",
    "--output",
    "--request-timeout",
    "--selector",
    "--server",
    "--token",
    "--user",
    "-l",
    "-n",
    "-o",
}
READ_COMMANDS = {
    "api-resources",
    "api-versions",
    "auth",
    "cluster-info",
    "describe",
    "explain",
    "get",
    "logs",
    "top",
    "version",
}
WRITE_COMMANDS = {
    "annotate",
    "apply",
    "autoscale",
    "cordon",
    "create",
    "drain",
    "edit",
    "expose",
    "label",
    "patch",
    "replace",
    "rollout",
    "scale",
    "set",
    "taint",
    "uncordon",
}
REMOTE_EXECUTE_COMMANDS = {"attach", "debug", "exec"}


@register("kubectl", pack="kubernetes")
def analyze_kubectl(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    subcommand = args[0].lower() if args else None
    targets = args[1:]
    namespace = option_value(invocation.args, "--namespace", short_names=("-n",)) or "default"
    context = option_value(invocation.args, "--context") or "current"
    kind = targets[0].lower() if targets else "*"
    name = targets[1] if len(targets) > 1 else "*"
    target = resource("kubernetes", context, namespace, kind, name)
    findings = []

    if subcommand in READ_COMMANDS:
        findings.append(evidence("infrastructure.read", f"kubectl {subcommand}", target))
        output = option_value(invocation.args, "--output", short_names=("-o",))
        if kind in {"secret", "secrets"} and output:
            findings.append(evidence("secret.read", "kubectl secret output", target))
    elif subcommand in WRITE_COMMANDS:
        findings.append(evidence("infrastructure.write", f"kubectl {subcommand}", target))
    elif subcommand == "delete":
        findings.append(evidence("infrastructure.delete", "kubectl delete", target))
        if flag_present(invocation.args, "--force"):
            findings.append(evidence("confirmation.bypass", "kubectl --force", target))
    elif subcommand in REMOTE_EXECUTE_COMMANDS:
        findings.extend(
            (
                evidence("network.connect", f"kubectl {subcommand}", target),
                evidence("remote.execute", f"kubectl {subcommand}", target),
            )
        )
    elif subcommand in {"port-forward", "proxy"}:
        findings.append(evidence("network.connect", f"kubectl {subcommand}", target))
    elif subcommand == "cp":
        findings.append(evidence("network.connect", "kubectl cp", target))
        if len(targets) >= 2:
            source, destination = targets[-2], targets[-1]
            source_remote = ":" in source
            destination_remote = ":" in destination
            if destination_remote and not source_remote:
                findings.append(evidence("network.upload", "kubectl cp upload", target))
            if source_remote and not destination_remote:
                findings.append(evidence("network.download", "kubectl cp download", target))

    return SemanticAnalysis(
        command="kubectl",
        subcommand=subcommand,
        flags=flags(invocation.args),
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="kubectl",
        notes=() if subcommand else ("kubectl subcommand not identified",),
    )
