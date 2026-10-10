"""Explicit, bounded, read-only inventory; static syntax never supplies policy.

No target imports, build scripts, hooks, remote links or instruction files are
executed. Python AST and limited text heuristics provide references, not a
reachability/data-flow proof. Raw source and literal values are not retained.
"""

from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ._files import ScopedFileError, _directory, _root, directory_entries, read_scoped_file
from ._json import digest
from .inventory_models import (
    InventoryFact,
    InventoryFile,
    InventoryIssue,
    InventoryLimits,
    RepositoryInventory,
    RepositoryThreatModel,
    RouteHypothesis,
)
from .models import (
    EvidenceLink,
    InvariantSelectors,
    ProtectedAsset,
    RepositoryScope,
    SecurityInvariant,
    SecurityProfileDraft,
    SourceReference,
    TrustBoundary,
)

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".aws",
    ".ssh",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".assurance-work",
    ".worktrees",
    ".runtime-cache",
    ".codex",
    ".agents",
    "build",
    "dist",
}
_SECRET_FILES = {".env", ".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"}
_SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".md",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".txt",
    ".lock",
}
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
_SINKS = {
    "subprocess.run": "subprocess.execute",
    "subprocess.Popen": "subprocess.execute",
    "subprocess.check_call": "subprocess.execute",
    "subprocess.check_output": "subprocess.execute",
    "os.system": "subprocess.execute",
    "os.execv": "subprocess.execute",
    "os.remove": "filesystem.delete",
    "os.unlink": "filesystem.delete",
    "shutil.rmtree": "filesystem.delete",
    "os.chmod": "filesystem.permission_change",
    "urllib.request.urlopen": "network.egress",
    "requests.get": "network.egress",
    "requests.post": "network.egress",
    "httpx.get": "network.egress",
    "httpx.post": "network.egress",
    "os.getenv": "environment.read",
}
_TAIL_SINKS = {
    "write_text": "filesystem.write",
    "write_bytes": "filesystem.write",
    "unlink": "filesystem.delete",
    "rmdir": "filesystem.delete",
    "execute": "database.mutation_candidate",
    "publish": "registry.publish_candidate",
    "send": "network.egress_candidate",
    "get_secret_value": "credential.reference",
}
_TRANSFORMS = {
    "json.loads": "serialization.parse",
    "json.load": "serialization.parse",
    "urllib.parse.urlsplit": "url.parse",
    "urllib.parse.urlparse": "url.parse",
    "shlex.split": "shell.parse",
}


@dataclass(frozen=True)
class AuthorizedRepository:
    """Host-selected root and revision. JSON repository fields do not establish it.

    virtual_root is the host's explicit POSIX action-space mapping, not inferred
    from local Windows paths. expected_snapshot_digest optionally pins all
    inspected bytes/coverage. The revision label alone is not Git attestation.
    """

    root: Path
    repository: RepositoryScope
    virtual_root: str
    expected_snapshot_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.root, Path)
            or not self.root.is_absolute()
            or not isinstance(self.repository, RepositoryScope)
        ):
            raise ValueError(
                "repository inventory requires a host-selected absolute root and scope"
            )
        ProtectedAsset("repository", "path", self.virtual_root, "prefix")
        _root(self.root)
        if PurePosixPath(self.virtual_root).as_posix() != self.virtual_root:
            raise ValueError("repository action-space mapping must be canonical")
        if self.expected_snapshot_digest is not None and not re.fullmatch(
            r"[a-f0-9]{64}", self.expected_snapshot_digest
        ):
            raise ValueError("invalid expected repository snapshot")


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _issue_path_digest(path: str) -> str:
    # Unsupported filenames may contain controls or undecodable bytes. Hash
    # those references without passing raw names into artifacts/diagnostics.
    return hashlib.sha256(
        b"ordin.assurance:excluded_path:v1\0" + path.encode("utf-8", "surrogatepass")
    ).hexdigest()


def _call_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _python_facts(text: str) -> list[tuple[str, str, int, str | None]]:
    # Preflight before AST allocation: bounded tokens, nesting and source bytes.
    depth = tokens = 0
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        tokens += 1
        if tokens > 20_000:
            raise ScopedFileError("source_parser_limit")
        if token.type == tokenize.OP:
            if token.string in {"(", "[", "{"}:
                depth += 1
            elif token.string in {")", "]", "}"}:
                depth -= 1
            if depth > 64:
                raise ScopedFileError("source_parser_limit")
    tree = ast.parse(text)
    aliases = {}
    node: ast.AST
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = node.module + "." + item.name
    facts: list[tuple[str, str, int, str | None]] = [
        ("control", "module.load_stop_candidate", node.lineno, None)
        for node in tree.body
        if isinstance(node, ast.Raise)
    ]
    pending: list[tuple[ast.AST, str | None]] = [(tree, None)]
    visited = 0
    while pending:
        node, enclosing = pending.pop()
        visited += 1
        if visited > 65_536 or len(facts) > 256:
            raise ScopedFileError("source_parser_limit")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            enclosing = node.name if _SYMBOL.fullmatch(node.name) else None
            decorators = [
                _call_name(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list
            ]
            if node.name in {
                "main",
                "cli",
                "handle_request",
                "handle_message",
                "webhook",
                "consume",
                "run_job",
            }:
                facts.append(("entrypoint", "handler.declaration", node.lineno, enclosing))
            if any(
                d.endswith((".get", ".post", ".route", ".put", ".delete", ".patch"))
                for d in decorators
            ):
                facts.append(("entrypoint", "http.handler_candidate", node.lineno, enclosing))
            if any(d.endswith((".tool", ".resource")) for d in decorators):
                facts.append(("entrypoint", "mcp.handler_candidate", node.lineno, enclosing))
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            head, _, tail = name.partition(".")
            name = aliases.get(head, head) + ("." + tail if tail else "")
            if name in _SINKS or name.rsplit(".", 1)[-1] in _TAIL_SINKS:
                category = _SINKS.get(name, _TAIL_SINKS.get(name.rsplit(".", 1)[-1]))
                facts.append(("sink", str(category), node.lineno, enclosing))
            if name in _TRANSFORMS:
                facts.append(("transformation", _TRANSFORMS[name], node.lineno, enclosing))
            if any(
                word in name.lower()
                for word in ("authoriz", "authenticat", "verify_runtime", "check_permission")
            ):
                facts.append(("control", "authorization.control_candidate", node.lineno, enclosing))
            if name == "open" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
                if isinstance(mode, str) and any(char in mode for char in "wax+"):
                    facts.append(("sink", "filesystem.write", node.lineno, enclosing))
        if isinstance(node, ast.If):
            names = [
                _call_name(child)
                for child in ast.walk(node.test)
                if isinstance(child, (ast.Name, ast.Attribute))
            ]
            if any(
                any(word in name.lower() for word in ("authoriz", "permission", "approval"))
                for name in names
            ):
                facts.append(("control", "approval.guard_candidate", node.lineno, enclosing))
        pending.extend((child, enclosing) for child in ast.iter_child_nodes(node))
    return sorted(set(facts), key=lambda fact: (fact[2], fact[0], fact[1], fact[3] or ""))


def _text_facts(path: str, text: str, language: str) -> list[tuple[str, str, int, str | None]]:
    result: list[tuple[str, str, int, str | None]] = []
    if path.rsplit("/", 1)[-1].lower() in {"readme.md", "agents.md", "security.md"}:
        if text:
            result.append(("instruction_data", "repository.instructions_untrusted", 1, None))
    if path.startswith(".github/workflows/") and text:
        result.append(("asset", "approval.workflow", 1, None))
    if language == "javascript":
        # Finite line heuristics deliberately label unparsed JS as candidates.
        for number, line in enumerate(text.splitlines(), 1):
            if any(word in line for word in ("child_process", "execFile(", "spawn(")):
                result.append(("sink", "subprocess.execute_candidate", number, None))
            if "fetch(" in line or "axios." in line:
                result.append(("sink", "network.egress_candidate", number, None))
            if any(word in line for word in ("writeFile(", "writeFileSync(", "unlink(")):
                result.append(("sink", "filesystem.mutation_candidate", number, None))
            if any(word in line for word in ("app.get(", "app.post(", "server.tool(")):
                result.append(("entrypoint", "handler.syntax_candidate", number, None))
            if any(word in line.lower() for word in ("authorize(", "checkpermission(")):
                result.append(("control", "authorization.control_candidate", number, None))
            if len(result) > 256:
                raise ScopedFileError("source_parser_limit")
    return result


def inventory_repository(
    scope: AuthorizedRepository, *, limits: InventoryLimits | None = None
) -> RepositoryInventory:
    if not isinstance(scope, AuthorizedRepository):
        raise ValueError("inventory requires an authorized repository object")
    limits = limits or InventoryLimits()
    if not isinstance(limits, InventoryLimits):
        raise ValueError("inventory requires typed limits")
    import os

    with _directory(scope.root) as (directory, directory_root):
        info = os.fstat(directory) if isinstance(directory, int) else directory_root.stat()
        root_identity = digest("repository_root_identity", [info.st_dev, info.st_ino])
    files: list[InventoryFile] = []
    facts: list[InventoryFact] = []
    issues: list[InventoryIssue] = []
    assets: list[ProtectedAsset] = []
    pending = [""]
    total_bytes = entries_seen = 0

    def issue(code: str, path: str = "") -> None:
        record = InventoryIssue(code, _issue_path_digest(path) if path else None)
        if record not in issues and len(issues) < 256:
            issues.append(record)

    def asset(kind: str, path: str, prefix: str) -> None:
        if len(assets) == 256:
            issue("source_asset_limit")
            return
        assets.append(
            ProtectedAsset(
                prefix + digest("source_path", path)[:24],
                kind,
                scope.virtual_root.rstrip("/") + "/" + path,
            )
        )

    while pending:
        directory_path = pending.pop(0)
        try:
            entries = directory_entries(scope.root, directory_path)
        except ScopedFileError as exc:
            issue(exc.code, directory_path)
            continue
        for entry in entries:
            entries_seen += 1
            if entries_seen > 4096:
                issue("source_entry_limit")
                pending.clear()
                break
            path = (directory_path + "/" if directory_path else "") + entry.name
            if entry.kind == "directory":
                if entry.name in _SKIP_DIRS:
                    issue("source_directory_excluded", path)
                elif path.count("/") >= limits.max_depth:
                    issue("source_depth_limit", path)
                else:
                    pending.append(path)
                continue
            if entry.kind != "file":
                issue("source_" + entry.kind + "_excluded", path)
                continue
            if (
                entry.name in _SECRET_FILES
                or entry.name.endswith((".pem", ".key", ".p12"))
                or entry.name.startswith(".env.")
            ):
                asset("path", path, "sensitive-")
                issue("sensitive_source_excluded", path)
                continue
            suffix = PurePosixPath(path).suffix.lower()
            if suffix not in _SOURCE_SUFFIXES:
                issue("source_language_unsupported", path)
                continue
            if len(files) >= limits.max_files:
                issue("source_file_count_limit")
                pending.clear()
                break
            try:
                content = read_scoped_file(scope.root, path)
                if total_bytes + len(content) > limits.max_total_bytes:
                    issue("source_total_bytes_limit")
                    pending.clear()
                    break
                total_bytes += len(content)
                text = content.decode("utf-8")
                language = (
                    "python"
                    if suffix == ".py"
                    else "javascript"
                    if suffix in {".js", ".ts", ".jsx", ".tsx"}
                    else "text"
                    if suffix == ".md"
                    else "configuration"
                )
                file = InventoryFile(
                    path, _sha(content), len(content), len(text.splitlines()), language
                )
                files.append(file)
                if path.startswith(".github/workflows/") or entry.name in {
                    "pyproject.toml",
                    "package.json",
                    "Dockerfile",
                }:
                    asset("policy", path, "config-")
                try:
                    discovered = (
                        _python_facts(text)
                        if language == "python"
                        else _text_facts(path, text, language)
                    )
                    if language == "javascript":
                        issue("javascript_syntax_only", path)
                    for kind, category, line, enclosing in discovered:
                        if len(facts) == 256:
                            issue("source_fact_limit")
                            break
                        source = SourceReference(
                            path, line, scope.repository.revision, file.content_digest, enclosing
                        )
                        facts.append(
                            InventoryFact(
                                "fact-"
                                + digest("inventory_fact", [source.as_dict(), kind, category])[:24],
                                kind,
                                category,
                                source,
                                enclosing,
                            )
                        )
                except (SyntaxError, tokenize.TokenError, RecursionError, ValueError) as exc:
                    issue(
                        exc.code if isinstance(exc, ScopedFileError) else "source_parse_incomplete",
                        path,
                    )
            except (ScopedFileError, UnicodeError) as exc:
                code = (
                    exc.code if isinstance(exc, ScopedFileError) else "source_encoding_unsupported"
                )
                issue(
                    "source_hardlink_excluded" if code == "source_hardlink_rejected" else code, path
                )
    files.sort(key=lambda file: file.path)
    facts.sort(key=lambda fact: (fact.source.path, fact.source.line, fact.fact_id))
    assets.sort(key=lambda asset: asset.id)
    issues.sort(key=lambda item: (item.code, item.path_digest or ""))
    material = {
        "repository": scope.repository.as_dict(),
        "files": [f.as_dict() for f in files],
        "issues": [item.as_dict() for item in issues],
        "assets": [a.as_dict() for a in assets],
        "limits": limits.as_dict(),
    }
    snapshot = digest("repository_snapshot", material)
    if scope.expected_snapshot_digest is not None and snapshot != scope.expected_snapshot_digest:
        raise ScopedFileError("repository_snapshot_mismatch")
    return RepositoryInventory(
        scope.repository,
        snapshot,
        root_identity,
        limits,
        tuple(files),
        tuple(facts),
        tuple(assets),
        tuple(issues),
        "partial" if issues else "complete",
    )


def verify_source_reference(scope: AuthorizedRepository, reference: SourceReference) -> bool:
    if not isinstance(scope, AuthorizedRepository) or not isinstance(reference, SourceReference):
        raise ValueError("source verification requires typed scope and reference")
    if reference.revision != scope.repository.revision:
        return False
    try:
        content = read_scoped_file(scope.root, reference.path)
        lines = content.decode("utf-8").splitlines()
        if _sha(content) != reference.content_digest or not 1 <= reference.line <= len(lines):
            return False
        if reference.symbol is not None:
            if PurePosixPath(reference.path).suffix != ".py":
                return False
            return any(
                line == reference.line and enclosing == reference.symbol
                for _, _, line, enclosing in _python_facts(content.decode("utf-8"))
            )
        return True
    except (ScopedFileError, UnicodeError, SyntaxError, tokenize.TokenError, RecursionError):
        return False


def build_threat_model(
    scope: AuthorizedRepository, inventory: RepositoryInventory
) -> RepositoryThreatModel:
    if not isinstance(inventory, RepositoryInventory) or scope.repository != inventory.repository:
        raise ValueError("threat model scope mismatch")
    # Reconstruct independently rather than trusting JSON-provided fact labels.
    current = inventory_repository(scope, limits=inventory.limits)
    if current.digest != inventory.digest:
        raise ScopedFileError("repository_inventory_stale_or_forged")
    actors = (
        "outside_attacker",
        "malicious_dependency_or_mcp_server",
        "compromised_sibling_agent",
        "unauthorized_insider",
    )
    boundaries = (
        TrustBoundary("external-input", "outside_attacker", "application_handler"),
        TrustBoundary("tool-to-executor", "malicious_dependency_or_mcp_server", "executor"),
        TrustBoundary("child-to-parent", "compromised_sibling_agent", "parent_agent"),
        TrustBoundary("repository-to-ci", "repository_data", "ci_runtime"),
    )
    entries = [f for f in inventory.facts if f.kind == "entrypoint"]
    controls = [f for f in inventory.facts if f.kind == "control"]
    routes = []
    for sink in (f for f in inventory.facts if f.kind == "sink"):
        colocated = [
            f
            for f in inventory.facts
            if f.source.path == sink.source.path and f.enclosing_symbol == sink.enclosing_symbol
        ]
        entry = next((f for f in colocated if f.kind == "entrypoint"), None)
        actor = (
            "malicious_dependency_or_mcp_server"
            if entry and entry.category.startswith("mcp.")
            else "outside_attacker"
        )
        routes.append(
            RouteHypothesis(
                "route-" + sink.fact_id[5:],
                actor,
                sink.fact_id,
                "tool-to-executor" if actor.startswith("malicious") else "external-input",
                entry.fact_id if entry else None,
                tuple(f.fact_id for f in colocated if f.kind == "transformation")[:32],
                tuple(f.fact_id for f in colocated if f.kind == "control")[:32],
            )
        )
    suggestions = []
    fact_by_path = {f.source.path: f for f in inventory.facts}
    for asset in inventory.assets:
        if asset.kind == "policy":
            relative = asset.value[len(scope.virtual_root.rstrip("/")) + 1 :]
            fact = fact_by_path.get(relative)
            provenance = (
                (
                    EvidenceLink(
                        "source-" + fact.fact_id[5:],
                        "static_evidence",
                        fact.source,
                        proof_gaps=("Deployment protections require operator review.",),
                    ),
                )
                if fact
                else ()
            )
            suggestions.append(
                SecurityInvariant(
                    "protect-" + asset.id,
                    "protected_policy_mutation",
                    InvariantSelectors(resource_ref=asset.id),
                    provenance=provenance,
                )
            )
    assumptions = (
        "The host supplied the repository revision and action-space mapping; no Git attestation is inferred.",
        "Static parsing establishes inspected syntax, not execution, authentication effectiveness or data flow.",
        "Deployment infrastructure, filesystem aliases and actual process privileges are uninspected.",
    )
    questions = (
        "Which inputs are attacker controlled and which handlers are externally reachable?",
        "Which host enforces filesystem, network, tool and credential constraints?",
        "Are candidate authorization controls unavoidable on each relevant route?",
        "Which assets are production and where are credentials mounted?",
        "How are child identities, grants and approval workflows authenticated?",
    )
    gaps = tuple(sorted({item.code for item in inventory.issues})) + questions
    draft = SecurityProfileDraft(
        "draft-" + inventory.snapshot_digest[:24],
        scope.repository,
        "ordin.static_inventory.v1",
        inventory.assets,
        boundaries,
        tuple(f.source for f in entries),
        tuple(
            f"{route.hypothesis_id}: possible source-to-sink route; reachability unverified."
            for route in routes
        ),
        tuple(dict.fromkeys(f.source for f in inventory.facts)),
        gaps,
        tuple(suggestions),
        completeness="partial" if inventory.issues else "unknown",
    )
    return RepositoryThreatModel(
        "model-" + inventory.snapshot_digest[:24],
        inventory,
        draft,
        actors,
        tuple(routes),
        tuple(f.fact_id for f in controls),
        assumptions,
        questions,
    )


def render_threat_model(model: RepositoryThreatModel, *, include_source_paths: bool = False) -> str:
    if not isinstance(model, RepositoryThreatModel) or type(include_source_paths) is not bool:
        raise ValueError("threat model rendering requires typed evidence and explicit privacy mode")

    def citation(source: SourceReference) -> str:
        path = (
            source.path
            if include_source_paths
            else "source-" + digest("source_path", source.path)[:12]
        )
        return f"`{path}:{source.line}` (bytes `{source.content_digest[:12]}`)"

    lines = [
        "# Repository threat-model draft",
        "",
        "Non-authoritative local static inventory.",
        "",
        f"Repository revision: `{model.inventory.repository.revision}`; snapshot: `{model.inventory.snapshot_digest}`.",
        f"Inspection coverage: {model.inventory.completeness}; {len(model.inventory.files)} files.",
        "",
        "## Inspected entrypoints, controls and sinks",
        "",
    ]
    for fact in model.inventory.facts:
        lines.append(f"- {fact.fact_id}: {fact.kind} / {fact.category}, {citation(fact.source)}")
    lines.extend(["", "## Actors and trust boundaries", ""])
    lines.extend(
        f"- {actor}: possible actor; actual control remains unverified." for actor in model.actors
    )
    lines.extend(
        f"- {b.id}: {b.source} -> {b.sink}; deployment enforcement unknown."
        for b in model.draft.trust_boundaries
    )
    lines.extend(["", "## Route hypotheses and strongest counterevidence", ""])
    for route in model.routes:
        lines.append(
            f"- {route.hypothesis_id}: {route.actor} -> {route.entrypoint_ref or 'unknown entrypoint'} "
            f"-> transformations {', '.join(route.transformation_refs) or 'unknown'} "
            f"-> controls {', '.join(route.control_refs) or 'uninspected'} -> {route.sink_ref}; hypothesis."
        )
        lines.extend(f"  - Proof gap: {gap}" for gap in route.proof_gaps)
    lines.extend(
        f"- Candidate counterevidence: {ref}; syntax does not prove this control stops the route."
        for ref in model.counterevidence_refs
    )
    lines.extend(["", "## Proposed assets and invariants", ""])
    for asset in model.draft.protected_assets:
        value = (
            asset.value
            if include_source_paths
            else "asset-" + digest("asset_value", asset.value)[:12]
        )
        lines.append(f"- {asset.id}: {asset.kind} / `{value}`; operator selection required.")
    lines.extend(
        f"- {rule.invariant_id}: {rule.kind}; suggestion only."
        for rule in model.draft.invariant_suggestions
    )
    for title, values in (
        ("Assumptions", model.assumptions),
        ("Open questions", model.open_questions),
        ("Coverage gaps", model.draft.unresolved_facts),
    ):
        lines.extend(["", "## " + title, ""])
        lines.extend("- " + value for value in values)
    lines.extend(
        [
            "",
            "Hashes are correlation aids, not encryption. No raw source or secret values are included.",
            "",
        ]
    )
    return "\n".join(lines)
