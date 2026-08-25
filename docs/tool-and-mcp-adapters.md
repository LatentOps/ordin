# Tool and MCP adapters

Ordin can normalize caller-owned agent tool calls into the same generic action review pipeline used by shell actions.

The adapter layer is intentionally execution-free. It does not connect to MCP servers, proxy traffic, store credentials, execute tools, or persist action history.

## Generic tool calls

```python
from ordin import AgentGate, ToolCallAdapter

adapter = ToolCallAdapter(runtime="coding-agent")
result = AgentGate().evaluate_tool(
    adapter,
    "read_file",
    {"path": "README.md"},
    intent="inspect project documentation",
)
```

An unclassified tool remains a generic `tool.call` action and therefore requires explicit approval rather than being silently treated as safe.

## MCP calls

```python
from ordin import AgentGate, MCPAdapter

adapter = MCPAdapter(server="filesystem")
result = AgentGate().evaluate_mcp(
    adapter,
    "read_file",
    {"path": "/tmp/example.txt"},
)
```

The resulting action keeps the MCP server, tool name, structured arguments, intent, context, and action ID available to the generic policy engine.

## Explicit shell-tool mappings

Some runtimes expose a tool whose documented contract is to execute shell command text. Ordin can unwrap only tool names the integrator explicitly configures:

```python
from ordin import AgentGate, MCPAdapter

adapter = MCPAdapter(
    server="local-shell",
    shell_tools=frozenset({"execute_command"}),
)

result = AgentGate().evaluate_mcp(
    adapter,
    "execute_command",
    {"command": "git reset --hard HEAD~1"},
)
```

This reuses the existing shell parser, analyzers, typed effects, context, temporal policy, and action policy. Similar-looking names are not matched implicitly.

The command field is configurable for runtimes that use another argument name:

```python
adapter = MCPAdapter(
    server="local-shell",
    shell_tools=frozenset({"run"}),
    command_argument="cmd",
)
```

## Trust boundary

Adapter configuration is part of the integration trust boundary. Mark a tool as a shell tool only when its documented semantics are exactly command execution. Ordin never infers this from substrings such as `shell`, `exec`, or `command`.

Structured arguments are bounded by the same JSON depth, item-count, key-length, and string-length limits as `ActionEnvelope`. Oversized or malformed payloads fail validation before review.

## Non-Python runtimes

Adapters are convenience helpers, not a separate protocol. Any runtime can build an `ordin.action_envelope.v1` payload and use the existing JSON interface:

```bash
cat action.json | ordin action --stdin --json --enforce
```

Unknown action semantics remain `ask`. Integrators can add deterministic semantics through the action/policy layers without bypassing the generic review contract.

## Runtime responsibilities

The integrating runtime remains responsible for:

- actual tool or command execution;
- sandbox configuration;
- human approval UI;
- retries and cancellation;
- MCP transport and authentication;
- action-history persistence.

Ordin's responsibility is local normalization, semantic review, policy evaluation, and a deterministic decision before execution.
