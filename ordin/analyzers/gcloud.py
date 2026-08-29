from __future__ import annotations

from . import register
from ._domain import cloud_direction, flags, positionals, resource, verb_effect
from .base import Invocation, SemanticAnalysis, evidence, option_value, unique_evidence


VALUE_OPTIONS = {
    "--account",
    "--billing-project",
    "--configuration",
    "--flags-file",
    "--format",
    "--impersonate-service-account",
    "--project",
    "--trace-token",
    "--verbosity",
}


@register("gcloud", pack="gcloud")
def analyze_gcloud(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    lowered = [item.lower() for item in args]
    project = option_value(invocation.args, "--project") or "default"
    target = resource("gcloud", project, "/".join(lowered[:4]) or "*")
    findings = []
    if args:
        findings.append(evidence("network.connect", "gcloud api request", target))

    joined = " ".join(lowered)
    if joined.startswith("auth print-access-token") or joined.startswith(
        "auth application-default print-access-token"
    ):
        findings.append(evidence("secret.read", "gcloud access token", "gcloud:credential"))
    elif joined.startswith("auth login") or joined.startswith("auth application-default login"):
        findings.append(evidence("secret.write", "gcloud credential login", "gcloud:credential"))
    elif "secrets versions access" in joined:
        findings.append(evidence("secret.read", "gcloud secret access", target))
    elif lowered[:2] in (["storage", "cp"], ["storage", "rsync"]):
        upload, download = cloud_direction(args[2:], "gs://")
        if upload:
            findings.append(evidence("network.upload", "gcloud storage upload", target))
        if download:
            findings.append(evidence("network.download", "gcloud storage download", target))
        if lowered[1] == "rsync":
            findings.append(evidence("infrastructure.write", "gcloud storage rsync", target))
    else:
        verb = next((item for item in lowered if verb_effect(item)), None)
        effect_name = verb_effect(verb) if verb else None
        if effect_name:
            permission_scope = any(
                "iam" in item or "policy" in item or "service-account" in item for item in lowered
            )
            if permission_scope and effect_name in {
                "infrastructure.delete",
                "infrastructure.write",
            }:
                findings.append(evidence("identity.permission_change", f"gcloud {verb}", target))
            else:
                findings.append(evidence(effect_name, f"gcloud {verb}", target))

    return SemanticAnalysis(
        command="gcloud",
        subcommand=" ".join(args[:3]) or None,
        flags=flags(invocation.args),
        targets=args[3:],
        evidence=unique_evidence(findings),
        analyzer="gcloud",
    )
