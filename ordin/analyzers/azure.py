from __future__ import annotations

from . import register
from ._domain import flags, positionals, resource, verb_effect
from .base import Invocation, SemanticAnalysis, evidence, option_value, unique_evidence


VALUE_OPTIONS = {"--output", "--query", "--subscription"}


@register("az", pack="azure")
def analyze_azure(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    lowered = [item.lower() for item in args]
    subscription = option_value(invocation.args, "--subscription") or "default"
    target = resource("azure", subscription, "/".join(lowered[:4]) or "*")
    findings = []
    if args:
        findings.append(evidence("network.connect", "az api request", target))

    joined = " ".join(lowered)
    if joined.startswith("account get-access-token"):
        findings.append(evidence("secret.read", "az access token", "azure:credential"))
    elif lowered[:3] == ["keyvault", "secret", "show"]:
        findings.append(evidence("secret.read", "az keyvault secret show", target))
    elif lowered[:3] == ["keyvault", "secret", "set"]:
        findings.append(evidence("secret.write", "az keyvault secret set", target))
    elif lowered[:3] in (["keyvault", "secret", "delete"], ["keyvault", "secret", "purge"]):
        findings.append(evidence("infrastructure.delete", "az keyvault secret removal", target))
    elif lowered[:3] == ["storage", "blob", "upload"]:
        findings.append(evidence("network.upload", "az storage blob upload", target))
    elif lowered[:3] == ["storage", "blob", "download"]:
        findings.append(evidence("network.download", "az storage blob download", target))
    else:
        verb = next((item for item in lowered if verb_effect(item)), None)
        effect_name = verb_effect(verb) if verb else None
        if effect_name:
            if any(item in {"ad", "identity", "role"} for item in lowered) and effect_name in {
                "infrastructure.delete",
                "infrastructure.write",
            }:
                findings.append(evidence("identity.permission_change", f"az {verb}", target))
            else:
                findings.append(evidence(effect_name, f"az {verb}", target))

    return SemanticAnalysis(
        command="az",
        subcommand=" ".join(args[:3]) or None,
        flags=flags(invocation.args),
        targets=args[3:],
        evidence=unique_evidence(findings),
        analyzer="az",
    )
