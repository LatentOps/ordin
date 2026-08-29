from __future__ import annotations

from . import register
from ._domain import flags, positionals, resource
from .base import Invocation, SemanticAnalysis, evidence, unique_evidence


VALUE_OPTIONS = {"--host", "--machine", "--root", "--state", "--type"}
READ_COMMANDS = {
    "cat",
    "help",
    "is-active",
    "is-enabled",
    "list-unit-files",
    "list-units",
    "show",
    "status",
}
CONTROL_COMMANDS = {
    "daemon-reload",
    "disable",
    "edit",
    "enable",
    "mask",
    "reload",
    "reload-or-restart",
    "restart",
    "set-property",
    "start",
    "stop",
    "try-restart",
    "unmask",
}
CONFIG_COMMANDS = {"disable", "edit", "enable", "mask", "set-property", "unmask"}
POWER_COMMANDS = {"halt", "hibernate", "hybrid-sleep", "poweroff", "reboot", "suspend"}


@register("systemctl", pack="systemd")
def analyze_systemctl(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    subcommand = args[0].lower() if args else None
    targets = args[1:]
    target = resource("service", targets[0] if targets else "*")
    findings = []
    if subcommand in READ_COMMANDS:
        findings.append(evidence("service.read", f"systemctl {subcommand}", target))
    elif subcommand in CONTROL_COMMANDS:
        findings.append(evidence("service.control", f"systemctl {subcommand}", target))
        if subcommand in CONFIG_COMMANDS:
            findings.append(
                evidence("system.configuration_write", f"systemctl {subcommand}", target)
            )
    elif subcommand in POWER_COMMANDS:
        findings.append(evidence("system.power_change", f"systemctl {subcommand}", "system"))
    return SemanticAnalysis(
        command="systemctl",
        subcommand=subcommand,
        flags=flags(invocation.args),
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="systemctl",
    )


@register("journalctl", pack="systemd")
def analyze_journalctl(invocation: Invocation) -> SemanticAnalysis:
    findings = [evidence("service.read", "journalctl", "system-journal")]
    if any(token.startswith("--vacuum-") for token in invocation.args):
        findings.append(evidence("infrastructure.delete", "journalctl vacuum", "system-journal"))
    if "--rotate" in invocation.args:
        findings.append(evidence("service.control", "journalctl --rotate", "system-journal"))
    return SemanticAnalysis(
        command="journalctl",
        subcommand=None,
        flags=flags(invocation.args),
        targets=(),
        evidence=unique_evidence(findings),
        analyzer="journalctl",
    )
