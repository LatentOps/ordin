from __future__ import annotations

import re

from . import register
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    unique_evidence,
)


def _operands(args: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    after_double_dash = False
    skip_next = False
    options_with_values = {"--reference", "--context"}
    for token in args:
        if skip_next:
            skip_next = False
            continue
        if after_double_dash:
            result.append(token)
            continue
        if token == "--":
            after_double_dash = True
            continue
        if token in options_with_values:
            skip_next = True
            continue
        if token.startswith("--reference=") or token.startswith("--context="):
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return tuple(result)


@register("rm")
def analyze_rm(invocation: Invocation) -> SemanticAnalysis:
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _operands(invocation.args)
    findings = []
    for target in targets or ("filesystem.target",):
        resource = f"path:{target}"
        findings.append(evidence("filesystem.delete", "rm target", resource))
        if flag_present(
            invocation.args,
            "--recursive",
            short_chars="rR",
        ):
            findings.append(
                evidence("filesystem.recursive_delete", "rm recursive flag", resource)
            )
    if flag_present(invocation.args, "--force", short_chars="f"):
        findings.append(evidence("confirmation.bypass", "rm force flag"))

    return SemanticAnalysis(
        command="rm",
        subcommand=None,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="rm",
    )


def _chmod_mode_and_targets(args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    operands = _operands(args)
    if not operands:
        return None, ()
    return operands[0], operands[1:]


def _broad_permission_mode(mode: str | None) -> bool:
    if not mode:
        return False
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return mode[-3:] == "777" or mode[-1] in {"6", "7"}
    normalized = mode.lower().replace(" ", "")
    return any(
        marker in normalized
        for marker in ("a+rwx", "ugo+rwx", "o+w", "o+rwx", "a+w")
    )


@register("chmod")
def analyze_chmod(invocation: Invocation) -> SemanticAnalysis:
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    mode, targets = _chmod_mode_and_targets(invocation.args)
    findings = []
    for target in targets or ("filesystem.target",):
        resource = f"path:{target}"
        findings.append(
            evidence("filesystem.permission_change", "chmod mode change", resource)
        )
        if flag_present(invocation.args, "--recursive", short_chars="R"):
            findings.append(
                evidence(
                    "filesystem.recursive_permission_change",
                    "chmod recursive flag",
                    resource,
                )
            )
    notes = ()
    if _broad_permission_mode(mode):
        notes = (f"permission mode {mode!r} broadly grants access",)
    return SemanticAnalysis(
        command="chmod",
        subcommand=None,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="chmod",
        notes=notes,
    )


@register("chown")
def analyze_chown(invocation: Invocation) -> SemanticAnalysis:
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    operands = _operands(invocation.args)
    owner = operands[0] if operands else None
    targets = operands[1:] if len(operands) > 1 else ()
    findings = []
    for target in targets or ("filesystem.target",):
        resource = f"path:{target}"
        findings.append(
            evidence("filesystem.ownership_change", "chown ownership change", resource)
        )
        if flag_present(invocation.args, "--recursive", short_chars="R"):
            findings.append(
                evidence(
                    "filesystem.recursive_ownership_change",
                    "chown recursive flag",
                    resource,
                )
            )
    notes = (f"owner specification: {owner}",) if owner else ()
    return SemanticAnalysis(
        command="chown",
        subcommand=None,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="chown",
        notes=notes,
    )
