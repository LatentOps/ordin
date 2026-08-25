# Generic action review

Ordin's generic action API lets callers describe a proposed action without requiring every integration to be modeled as shell text. The shell command engine remains a first-class adapter and preserves its existing public behavior.

## Action envelope

A generic action uses `ordin.action_envelope.v1`:

```json
{
  "schema_version": "ordin.action_envelope.v1",
  "action_id": "build-cleanup-1",
  "kind": "shell",
  "operation": "execute",
  "parameters": {
    "command": "rm -rf ./build"
  },
  "intent": "remove generated build output",
  "context": {
    "cwd": "/workspace/repo",
    "shell": "bash",
    "euid": 1000,
    "interactive": false,
    "repo_root": "/workspace/repo",
    "agent": "coding-agent"
  }
}
```

The initial vocabulary recognizes common action families such as `shell`, `file`, `network`, `mcp`, `database`, and `tool`. The schema intentionally permits future action kinds so newer integrations do not have to masquerade as shell commands.

Recognition of a kind is not recognition of its semantics. If Ordin does not have a deterministic adapter for the exact action, the review is `ask` with `unknown` risk. Unknown actions never become implicitly safe.

## Python API

```python
from ordin import ActionEnvelope, Ordin

ordin = Ordin()
action = ActionEnvelope.shell(
    "git status --short",
    intent="inspect repository state",
)
review = ordin.review_action(action)

assert review.adapter == "shell"
assert review.capabilities is not None
```

Mappings are accepted too, but mapping inputs are validated against the public envelope schema before review.

`Ordin.review_action` is side-effect free. It never executes the described action.

## CLI and JSON

A non-Python caller can review a versioned action through stdin:

```bash
cat action.json | ordin action --stdin --json
```

Enforcement uses the same exit-code contract as command review:

```bash
cat action.json | ordin action --stdin --json --enforce
```

The output uses `ordin.action_review.v1` and includes:

- the normalized input envelope;
- `allow`, `warn`, `ask`, or `block`;
- risk level and reasons;
- typed effects when an adapter can establish them;
- structured resources derived from semantic evidence;
- the adapter responsible for classification;
- an advisory execution capability profile;
- intent-alignment and trajectory categories when available from the underlying adapter.

Capability profiles describe the minimum class of filesystem, network, privilege, and process capabilities Ordin can infer from typed effects/resources. They are advisory only. The caller owns actual sandbox enforcement. See [Execution capability profiles and observations](execution-evidence.md).

## Shell adapter

`kind=shell` with `operation=execute` requires `parameters.command`.

The adapter calls the same `review_command` engine used by the existing CLI and Python command API. It does not maintain a second shell risk implementation. The generic review then exposes normalized typed effects and resources for later policy layers.

For example, a reviewed filesystem mutation can expose effects such as:

```text
filesystem.delete
filesystem.recursive_delete
```

and a resource such as:

```text
path:/workspace/repo/build
```

## Tool and MCP adapters

Generic tool and MCP actions normalize through the public `ToolCallAdapter` and `MCPAdapter`. Trusted local semantics may be supplied through `ToolSemanticsRegistry` so exact runtime/server identities can produce typed effects/resources without allowing untrusted call arguments to declare their own safety labels.

See [Tool and MCP adapters](tool-and-mcp-adapters.md).

## Conservative extension contract

New adapters should follow these rules:

1. **Never execute the action.** An adapter only normalizes and reviews caller-supplied data.
2. **Do not trust caller-provided risk labels or effects.** Derive semantics from deterministic adapter logic or curated Ordin metadata.
3. **Fail closed.** If the adapter cannot establish semantics, return `ask` rather than inventing low risk.
4. **Reuse the effect vocabulary.** Prefer shared effects such as `filesystem.delete` or `network.upload` over adapter-specific duplicates.
5. **Expose resources separately from effects.** Policies should be able to reason about both what happens and what it targets.
6. **Bound inputs.** Parameter depth, collection sizes, identifier sizes, and string sizes must remain finite and validated.
7. **Keep the core local-first.** Adapters must not require telemetry, hosted inference, remote schema discovery, or network access.
8. **Preserve existing contracts.** Adding a generic adapter must not weaken the established command-review result for an equivalent shell action.
9. **Add offline tests.** Cover safe, risky, unknown, malformed, schema, and installed-package behavior.
10. **Document public semantics.** Any new action kind or operation that can produce a confident review needs a stable explanation and examples.

## Schema files

The public contracts live in:

- `schemas/action-envelope.v1.schema.json`
- `schemas/action-history.v1.schema.json`
- `schemas/action-review.v1.schema.json`
- `schemas/execution-capabilities.v1.schema.json`
- `schemas/action-observation.v1.schema.json`
- `schemas/observation-history.v1.schema.json`

Packaged copies are validated for parity by `ordin doctor` and CI.
