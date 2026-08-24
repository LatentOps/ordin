from __future__ import annotations

from . import register
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    unique_evidence,
)


PIP_SUBCOMMANDS = {
    "install",
    "uninstall",
    "list",
    "show",
    "freeze",
    "check",
    "download",
    "wheel",
    "inspect",
}
NPM_SUBCOMMANDS = {
    "install",
    "i",
    "add",
    "ci",
    "uninstall",
    "remove",
    "rm",
    "un",
    "list",
    "ls",
    "view",
    "info",
    "outdated",
    "run",
    "run-script",
    "exec",
    "pack",
    "audit",
}
APT_SUBCOMMANDS = {
    "install",
    "remove",
    "purge",
    "autoremove",
    "update",
    "upgrade",
    "full-upgrade",
    "dist-upgrade",
    "download",
    "source",
    "list",
    "show",
    "search",
}


def _find_subcommand(
    args: tuple[str, ...],
    candidates: set[str],
) -> tuple[str | None, tuple[str, ...]]:
    for index, token in enumerate(args):
        if token in candidates:
            return token, args[index + 1:]
    return None, ()


def _targets(args: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(token for token in args if not token.startswith("-"))


@register("pip")
def analyze_pip(invocation: Invocation) -> SemanticAnalysis:
    subcommand, args = _find_subcommand(invocation.args, PIP_SUBCOMMANDS)
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _targets(args)
    findings = []
    dry_run = flag_present(args, "--dry-run")

    if subcommand == "install":
        if dry_run:
            findings.append(evidence("package.read", "pip install --dry-run"))
            findings.append(evidence("network.connect", "pip dependency resolution"))
        else:
            findings.append(evidence("package.install", "pip install"))
            findings.append(evidence("code.execute", "pip package build/install hooks"))
    elif subcommand == "uninstall":
        findings.append(evidence("package.remove", "pip uninstall"))
        if flag_present(args, "-y", "--yes", short_chars="y"):
            findings.append(evidence("confirmation.bypass", "pip uninstall --yes"))
    elif subcommand in {"list", "show", "freeze", "check", "inspect"}:
        findings.append(evidence("package.read", f"pip {subcommand}"))
    elif subcommand == "download":
        findings.extend(
            [
                evidence("network.download", "pip download"),
                evidence("filesystem.write", "pip download destination"),
            ]
        )
    elif subcommand == "wheel":
        findings.extend(
            [
                evidence("code.execute", "pip wheel build"),
                evidence("filesystem.write", "pip wheel output"),
            ]
        )

    return SemanticAnalysis(
        command="pip",
        subcommand=subcommand,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="pip",
    )


@register("npm")
def analyze_npm(invocation: Invocation) -> SemanticAnalysis:
    subcommand, args = _find_subcommand(invocation.args, NPM_SUBCOMMANDS)
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _targets(args)
    findings = []
    dry_run = flag_present(args, "--dry-run")
    ignore_scripts = flag_present(args, "--ignore-scripts")

    if subcommand in {"install", "i", "add", "ci"}:
        if dry_run:
            findings.extend(
                [
                    evidence("package.read", "npm install --dry-run"),
                    evidence("network.connect", "npm package resolution"),
                ]
            )
        else:
            findings.append(evidence("package.install", f"npm {subcommand}"))
            if not ignore_scripts:
                findings.append(
                    evidence("code.execute", "npm lifecycle/package scripts")
                )
    elif subcommand in {"uninstall", "remove", "rm", "un"}:
        findings.append(evidence("package.remove", f"npm {subcommand}"))
    elif subcommand in {"list", "ls", "view", "info", "outdated"}:
        findings.append(evidence("package.read", f"npm {subcommand}"))
    elif subcommand in {"run", "run-script", "exec"}:
        findings.append(evidence("code.execute", f"npm {subcommand}"))
    elif subcommand == "pack":
        findings.append(evidence("filesystem.write", "npm pack output"))
    elif subcommand == "audit":
        findings.append(evidence("network.connect", "npm audit"))

    return SemanticAnalysis(
        command="npm",
        subcommand=subcommand,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="npm",
    )


@register("apt", "apt-get")
def analyze_apt(invocation: Invocation) -> SemanticAnalysis:
    subcommand, args = _find_subcommand(invocation.args, APT_SUBCOMMANDS)
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _targets(args)
    findings = []
    simulate = flag_present(
        invocation.args,
        "-s",
        "--simulate",
        "--dry-run",
        "--just-print",
        "--no-act",
        short_chars="s",
    )

    if simulate and subcommand in {
        "install",
        "remove",
        "purge",
        "autoremove",
        "upgrade",
        "full-upgrade",
        "dist-upgrade",
    }:
        findings.append(evidence("package.read", f"{invocation.executable} simulated {subcommand}"))
    elif subcommand == "install":
        findings.append(evidence("package.install", f"{invocation.executable} install"))
    elif subcommand in {"remove", "purge", "autoremove"}:
        findings.append(evidence("package.remove", f"{invocation.executable} {subcommand}"))
        if flag_present(invocation.args, "-y", "--yes", "--assume-yes", short_chars="y"):
            findings.append(evidence("confirmation.bypass", "apt assume-yes"))
    elif subcommand == "update":
        findings.extend(
            [
                evidence("network.download", f"{invocation.executable} update"),
                evidence("package.read", "apt package index"),
            ]
        )
    elif subcommand in {"upgrade", "full-upgrade", "dist-upgrade"}:
        findings.append(evidence("package.install", f"{invocation.executable} {subcommand}"))
    elif subcommand in {"download", "source"}:
        findings.extend(
            [
                evidence("network.download", f"{invocation.executable} {subcommand}"),
                evidence("filesystem.write", f"{invocation.executable} {subcommand} output"),
            ]
        )
    elif subcommand in {"list", "show", "search"}:
        findings.append(evidence("package.read", f"{invocation.executable} {subcommand}"))

    return SemanticAnalysis(
        command=invocation.executable,
        subcommand=subcommand,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="apt",
    )
