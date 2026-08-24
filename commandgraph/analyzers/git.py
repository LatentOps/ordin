from __future__ import annotations

from . import register
from .base import (
    Invocation,
    SemanticAnalysis,
    evidence,
    flag_present,
    unique_evidence,
)


GLOBAL_VALUE_OPTIONS = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
}
READ_SUBCOMMANDS = {
    "status",
    "diff",
    "log",
    "show",
    "reflog",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "describe",
    "blame",
    "grep",
}
LOCAL_WRITE_SUBCOMMANDS = {
    "add",
    "commit",
    "checkout",
    "switch",
    "restore",
    "merge",
    "cherry-pick",
    "revert",
    "stash",
}
HISTORY_REWRITE_SUBCOMMANDS = {
    "rebase",
    "filter-branch",
}


def _split_git_args(args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if not token.startswith("-"):
            break
        key = token.split("=", 1)[0]
        if key in GLOBAL_VALUE_OPTIONS and "=" not in token:
            index += 2
        else:
            index += 1
    if index >= len(args):
        return None, ()
    return args[index], args[index + 1:]


def _targets(args: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(token for token in args if not token.startswith("-"))


@register("git")
def analyze_git(invocation: Invocation) -> SemanticAnalysis:
    subcommand, args = _split_git_args(invocation.args)
    flags = tuple(token for token in invocation.args if token.startswith("-"))
    targets = _targets(args)
    findings = []

    if subcommand in READ_SUBCOMMANDS:
        findings.append(evidence("git.read", f"git {subcommand}"))

    elif subcommand == "branch":
        mutation = flag_present(
            args,
            "-d",
            "-D",
            "-m",
            "-M",
            "-c",
            "-C",
        )
        findings.append(
            evidence(
                "git.local_write" if mutation else "git.read",
                "git branch mutation" if mutation else "git branch read",
            )
        )

    elif subcommand == "reset":
        findings.append(evidence("git.local_write", "git reset"))
        if flag_present(args, "--hard"):
            findings.append(evidence("git.history_rewrite", "git reset --hard"))

    elif subcommand == "clean":
        findings.append(
            evidence("filesystem.delete", "git clean", "git.working_tree")
        )
        if flag_present(args, "-d", short_chars="d"):
            findings.append(
                evidence(
                    "filesystem.recursive_delete",
                    "git clean directory flag",
                    "git.working_tree",
                )
            )
        if flag_present(args, "-f", "--force", short_chars="f"):
            findings.append(evidence("confirmation.bypass", "git clean force flag"))

    elif subcommand == "push":
        findings.append(evidence("git.remote_write", "git push"))
        if flag_present(
            args,
            "--force",
            "--force-with-lease",
            short_chars="f",
        ):
            findings.append(evidence("git.history_rewrite", "git force push"))

    elif subcommand in LOCAL_WRITE_SUBCOMMANDS:
        findings.append(evidence("git.local_write", f"git {subcommand}"))

    elif subcommand in HISTORY_REWRITE_SUBCOMMANDS:
        findings.append(evidence("git.history_rewrite", f"git {subcommand}"))

    elif subcommand == "clone":
        findings.extend(
            [
                evidence("network.download", "git clone"),
                evidence("filesystem.write", "git clone destination"),
            ]
        )

    elif subcommand == "fetch":
        findings.extend(
            [
                evidence("network.download", "git fetch"),
                evidence("git.local_write", "git fetch references"),
            ]
        )

    elif subcommand == "pull":
        findings.extend(
            [
                evidence("network.download", "git pull"),
                evidence("git.local_write", "git pull"),
            ]
        )

    elif subcommand == "remote":
        mutation = bool(args) and args[0] in {
            "add",
            "remove",
            "rm",
            "rename",
            "set-head",
            "set-url",
            "prune",
        }
        findings.append(
            evidence(
                "git.local_write" if mutation else "git.read",
                "git remote mutation" if mutation else "git remote read",
            )
        )

    elif subcommand == "tag":
        mutation = flag_present(args, "-d", "-f", "--delete", "--force", short_chars="df")
        findings.append(
            evidence(
                "git.history_rewrite" if mutation else "git.read",
                "git tag mutation" if mutation else "git tag read",
            )
        )

    elif subcommand == "config":
        read_only = flag_present(
            args,
            "--get",
            "--get-all",
            "--get-regexp",
            "--list",
            "-l",
            short_chars="l",
        )
        findings.append(
            evidence(
                "git.read" if read_only else "git.local_write",
                "git config read" if read_only else "git config write",
            )
        )

    return SemanticAnalysis(
        command="git",
        subcommand=subcommand,
        flags=flags,
        targets=targets,
        evidence=unique_evidence(findings),
        analyzer="git",
        notes=() if subcommand else ("git subcommand not identified",),
    )
