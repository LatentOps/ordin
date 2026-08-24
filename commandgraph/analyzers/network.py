from __future__ import annotations

from . import register
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    option_value,
    unique_evidence,
)


CURL_VALUE_OPTIONS = {
    "-o",
    "--output",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-F",
    "--form",
    "-T",
    "--upload-file",
    "-X",
    "--request",
    "-H",
    "--header",
    "-A",
    "--user-agent",
    "-u",
    "--user",
}
WGET_VALUE_OPTIONS = {
    "-O",
    "--output-document",
    "--post-data",
    "--post-file",
    "--body-data",
    "--body-file",
    "--header",
    "--user",
    "--password",
}


def _non_option_values(
    args: tuple[str, ...],
    options_with_values: set[str],
) -> tuple[str, ...]:
    values: list[str] = []
    skip_next = False
    for token in args:
        if skip_next:
            skip_next = False
            continue
        key = token.split("=", 1)[0]
        if key in options_with_values:
            if "=" not in token:
                skip_next = True
            continue
        if any(
            token.startswith(short)
            and token != short
            for short in options_with_values
            if short.startswith("-") and not short.startswith("--") and len(short) == 2
        ):
            continue
        if token == "--":
            continue
        if not token.startswith("-"):
            values.append(token)
    return tuple(values)


@register("curl")
def analyze_curl(invocation: Invocation) -> SemanticAnalysis:
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _non_option_values(invocation.args, CURL_VALUE_OPTIONS)
    findings = [evidence("network.connect", "curl request")]

    uploads = flag_present(
        invocation.args,
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "-T",
        "--upload-file",
    ) or any(
        option_value(invocation.args, short_names=(short,)) is not None
        for short in ("-d", "-F", "-T")
    )
    if uploads:
        findings.append(evidence("network.upload", "curl request body/upload"))

    output = option_value(
        invocation.args,
        "--output",
        short_names=("-o",),
    )
    remote_name = flag_present(
        invocation.args,
        "-O",
        "--remote-name",
    )
    if output is not None or remote_name:
        findings.append(evidence("network.download", "curl output"))
        findings.append(
            evidence(
                "filesystem.write",
                "curl output file",
                f"path:{output}" if output else "path:remote-name",
            )
        )

    return SemanticAnalysis(
        command="curl",
        subcommand=None,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="curl",
    )


@register("wget")
def analyze_wget(invocation: Invocation) -> SemanticAnalysis:
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _non_option_values(invocation.args, WGET_VALUE_OPTIONS)
    findings = [evidence("network.connect", "wget request")]

    spider = flag_present(invocation.args, "--spider")
    if not spider:
        findings.append(evidence("network.download", "wget download"))

    output = option_value(
        invocation.args,
        "--output-document",
        short_names=("-O",),
    )
    if not spider and output != "-":
        findings.append(
            evidence(
                "filesystem.write",
                "wget output file",
                f"path:{output}" if output else "path:remote-name",
            )
        )

    if flag_present(
        invocation.args,
        "--post-data",
        "--post-file",
        "--body-data",
        "--body-file",
    ):
        findings.append(evidence("network.upload", "wget request body/upload"))

    return SemanticAnalysis(
        command="wget",
        subcommand=None,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="wget",
    )
