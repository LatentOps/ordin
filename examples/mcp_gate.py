from ordin import AgentGate, MCPAdapter


adapter = MCPAdapter(
    server="local-shell",
    shell_tools=frozenset({"execute_command"}),
)

decision = AgentGate().evaluate_mcp(
    adapter,
    "execute_command",
    {"command": "git status --short"},
    intent="inspect repository state",
)

print(decision.disposition)
print(decision.review.as_dict())
