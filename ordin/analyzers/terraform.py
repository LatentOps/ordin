from __future__ import annotations

from . import register
from ._domain import flags, positionals, resource
from .base import Invocation, SemanticAnalysis, evidence, flag_present, unique_evidence


VALUE_OPTIONS = {"-chdir", "-var", "-var-file"}
READ_COMMANDS = {"graph", "plan", "providers", "show", "validate", "version"}
READ_PAIRS = {"state list", "state pull", "state show", "workspace list", "workspace show"}
WRITE_COMMANDS = {"apply", "force-unlock", "fmt", "import", "refresh", "taint", "untaint"}
WRITE_PAIRS = {
    "state mv",
    "state push",
    "state replace-provider",
    "workspace new",
    "workspace select",
}
DELETE_PAIRS = {"state rm", "workspace delete"}


def analyze_terraform(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    subcommand = args[0].lower() if args else None
    second = args[1].lower() if len(args) > 1 else None
    combined = f"{subcommand} {second}" if subcommand and second else subcommand
    target = resource("terraform", invocation.executable, combined or "*")
    findings = []

    if subcommand in READ_COMMANDS or combined in READ_PAIRS:
        findings.append(
            evidence("infrastructure.read", f"{invocation.executable} {combined}", target)
        )
    elif subcommand == "output":
        findings.append(evidence("infrastructure.read", f"{invocation.executable} output", target))
        if flag_present(invocation.args, "-raw", "-json"):
            findings.append(evidence("secret.read", f"{invocation.executable} output", target))
    elif subcommand == "init":
        findings.extend(
            (
                evidence("network.download", f"{invocation.executable} init", target),
                evidence("filesystem.write", f"{invocation.executable} init", "path:.terraform"),
            )
        )
    elif subcommand == "destroy" or combined in DELETE_PAIRS:
        findings.append(
            evidence("infrastructure.delete", f"{invocation.executable} {combined}", target)
        )
    elif subcommand in WRITE_COMMANDS or combined in WRITE_PAIRS:
        findings.append(
            evidence("infrastructure.write", f"{invocation.executable} {combined}", target)
        )

    if subcommand in {"apply", "destroy"} and flag_present(invocation.args, "-auto-approve"):
        findings.append(
            evidence("confirmation.bypass", f"{invocation.executable} -auto-approve", target)
        )

    return SemanticAnalysis(
        command=invocation.executable,
        subcommand=combined,
        flags=flags(invocation.args),
        targets=args[1:],
        evidence=unique_evidence(findings),
        analyzer=invocation.executable,
        notes=() if subcommand else (f"{invocation.executable} subcommand not identified",),
    )


register("terraform", pack="terraform")(analyze_terraform)
register("tofu", pack="terraform")(analyze_terraform)
