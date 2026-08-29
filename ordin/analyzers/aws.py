from __future__ import annotations

from . import register
from ._domain import cloud_direction, flags, positionals, resource, verb_effect
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    option_value,
    unique_evidence,
)


VALUE_OPTIONS = {
    "--ca-bundle",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "--color",
    "--endpoint-url",
    "--output",
    "--profile",
    "--query",
    "--region",
}


@register("aws", pack="aws")
def analyze_aws(invocation: Invocation) -> SemanticAnalysis:
    args = positionals(invocation.args, VALUE_OPTIONS)
    service = args[0].lower() if args else None
    operation = args[1].lower() if len(args) > 1 else None
    region = option_value(invocation.args, "--region") or "default"
    target = resource("aws", service or "*", region, operation or "*")
    findings = []
    if service and operation:
        findings.append(evidence("network.connect", "aws api request", target))

    if service == "configure":
        findings.extend(
            (
                evidence("secret.write", "aws configure", "aws:credential"),
                evidence("filesystem.write", "aws configure", "path:~/.aws"),
            )
        )
    elif service == "secretsmanager" and operation in {
        "batch-get-secret-value",
        "get-secret-value",
    }:
        findings.append(evidence("secret.read", "aws secretsmanager read", target))
    elif (
        service == "ssm"
        and operation in {"get-parameter", "get-parameters"}
        and flag_present(invocation.args, "--with-decryption")
    ):
        findings.append(evidence("secret.read", "aws ssm decrypted parameter", target))
    elif service == "sts" and operation and "token" in operation:
        findings.append(evidence("secret.read", "aws sts token", target))
    elif service == "s3" and operation in {"cp", "mv", "sync"}:
        upload, download = cloud_direction(args[2:], "s3://")
        if upload:
            findings.append(evidence("network.upload", f"aws s3 {operation}", target))
        if download:
            findings.append(evidence("network.download", f"aws s3 {operation}", target))
        if operation in {"mv", "sync"}:
            findings.append(evidence("infrastructure.write", f"aws s3 {operation}", target))
    elif service == "s3" and operation in {"rb", "rm"}:
        findings.append(evidence("infrastructure.delete", f"aws s3 {operation}", target))
    elif service == "s3" and operation == "ls":
        findings.append(evidence("infrastructure.read", "aws s3 ls", target))
    elif service in {"iam", "organizations"} and operation:
        effect_name = verb_effect(operation)
        if effect_name in {"infrastructure.delete", "infrastructure.write"}:
            findings.append(
                evidence("identity.permission_change", f"aws {service} {operation}", target)
            )
        elif effect_name:
            findings.append(evidence(effect_name, f"aws {service} {operation}", target))
    elif service == "lambda" and operation == "invoke":
        findings.append(evidence("remote.execute", "aws lambda invoke", target))
    elif operation:
        effect_name = verb_effect(operation)
        if effect_name:
            findings.append(evidence(effect_name, f"aws {service} {operation}", target))

    return SemanticAnalysis(
        command="aws",
        subcommand=f"{service} {operation}" if operation else service,
        flags=flags(invocation.args),
        targets=args[2:],
        evidence=unique_evidence(findings),
        analyzer="aws",
    )
