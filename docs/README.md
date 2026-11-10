# Ordin documentation

Start with what you are trying to do. The implementation details are linked after the user-facing paths.

## I want to install Ordin or use it from a terminal

- [Installation](installation.md)
- [Verified v0.4 core/Swarm artifact quickstart](quickstart-0.4.md)
- [Offline v0.3 quickstart](quickstart.md)
- [Platform and integration compatibility](compatibility.md)
- [Setup, smoke checks, status, and removal (0.4 candidate)](setup.md)
- [Report a failure safely](feedback-intake.md)
- [Bare intent CLI](bare-intent-cli.md)
- [Generic action review](action-review.md)
- [Declarative action policies](policies.md)
- [Temporal action policies](temporal-policies.md)
- [Interactive shell integration](shell-integration.md)
- [Enforcement and exit codes](enforcement.md)

Typical commands:

```bash
ordin what is using port 3000
ordin check "git reset --hard HEAD~1"
cat action.json | ordin action --stdin --json
ordin policy validate examples/policy.json
ordin temporal validate data/temporal_policies.json
source <(ordin shell-init bash)
orun 'git status --short'
```

## I want to embed Ordin in an application

- [Python API](python-api.md)
- [Generic action review](action-review.md)
- [Execution capability profiles and observations](execution-evidence.md)
- [Versioned runtime capabilities](runtime-capabilities.md)
- [GraphQL/MCP request contracts and boundaries](runtime-requests.md)
- [Optional OCSF finding export](ocsf-export.md)
- [Trusted runtime evidence and correlation](runtime-evidence.md)
- [Capability boundary verification](runtime-boundaries.md)
- [Minimal denial proposals](capability-proposals.md)
- [Backend protocol](enforcement-backends.md)
- [Optional Ordin Runtime compiler, prover, events, and shadow evaluation](runtime-integration.md)
- [Runtime capability benchmark and recorded workload](runtime-capability-benchmark.md)
- [Ordin Runtime demo and evidence](runtime-demo.md)
- [Runtime enforcement requirement and invariant audit](runtime-enforcement-acceptance.md)
- [Runtime enforcement adversarial corpus](runtime-enforcement-corpus.md)
- [Runtime machine reason codes](runtime-reason-codes.md)
- [Decision provenance and local audit evidence](audit-and-provenance.md)
- [Tool and MCP adapters](tool-and-mcp-adapters.md)
- [Declarative action policies](policies.md)
- [Temporal action policies](temporal-policies.md)
- [Schema contracts](schema-contracts.md)
- [v0.3 public compatibility surface](public-compatibility-0.3.md)
- [v0.4 public contracts, migration and rollback](public-compatibility-0.4.md)
- [Context-aware review](context-aware-review.md)
- [Trace-aware review](trace-aware-review.md)

The Python API reviews actions but never executes them.

## I want to gate an AI agent

- [Protected host enrollment and agent lifecycle](swarm/identity.md)
- [Authenticated swarm events, journal and causal gaps](swarm/events.md)
- [Pure swarm decision composition and mandatory checks](swarm/gate.md)
- [Protected tool gateway and MCP/hook adapters](swarm/gateway.md)
- [Authenticated cross-agent causal graph](swarm/causal-graph.md)
- [Cross-agent sensitivity labels and mediated egress](swarm/source-flow.md)
- [Late attach, event continuity and coverage diagnostics](swarm/late-attach.md)
- [Authenticated inter-agent data messages and transports](swarm/messages.md)
- [Declarative swarm policy, precedence and safe reload](swarm/policies.md)
- [Pinned framework adapters and the protected runtime SDK](swarm/framework-adapters.md)
- [Online delegation, workload authentication and private credentials](swarm/distributed-delegation.md)
- [Guarded artifacts, shared memory and workspaces](swarm/artifacts.md)
- [Cross-agent causal temporal policies](swarm/temporal.md)
- [Transactional shared budgets and reservations](swarm/budgets.md)
- [Scoped containment, owned-job status and protected recovery](swarm/containment.md)
- [Private audit, authenticated operator API, diagnostics and local exports](swarm/operations.md)
- [Planned opt-in swarm architecture and coverage contract](swarm/architecture.md)
- [Integration starter kit](../examples/integrations/README.md)
- [Claude Code hooks](claude-code-integration.md)
- [Codex hooks and plugin](codex-integration.md)
- [Cursor native hooks (0.4)](cursor-integration.md)
- [Hermes Agent native hooks (0.4)](hermes-integration.md)
- [Live integration sessions](integration-sessions.md)
- [MCP safety proxy](mcp-safety-proxy.md)
- [MCP Streamable HTTP proxy](mcp-http-proxy.md)
- [MCP contract pinning](mcp-contract-pinning.md)
- [MCP inspection and semantics setup](mcp-semantics-setup.md)
- [Integration diagnostics](integration-troubleshooting.md)
- [Agent runtime integration](agent-integration.md)
- [Tool and MCP adapters](tool-and-mcp-adapters.md)
- [Execution capability profiles and observations](execution-evidence.md)
- [Decision provenance and local audit evidence](audit-and-provenance.md)
- [Generic action review](action-review.md)
- [Declarative action policies](policies.md)
- [Temporal action policies](temporal-policies.md)
- [Python API](python-api.md)
- [Trace-aware review](trace-aware-review.md)
- [Enforcement and exit codes](enforcement.md)

The canonical integration is:

```text
agent proposes action -> Ordin -> execute / escalate / deny -> caller runtime
```

Review APIs return decisions without executing actions. The optional shell
wrapper executes reviewed commands, and the MCP proxy relays stdio traffic to
its configured server. The runtime owns sandboxing, credentials, and approvals.

## I want to understand how Ordin decides

- [Architecture](architecture.md)
- [Generic action review](action-review.md)
- [Execution capability profiles and observations](execution-evidence.md)
- [Decision provenance and local audit evidence](audit-and-provenance.md)
- [Declarative action policies](policies.md)
- [Temporal action policies](temporal-policies.md)
- [Typed effect graph](effect-graph.md)
- [Semantic analyzers](semantic-analyzers.md)
- [Context-aware review](context-aware-review.md)
- [Trace-aware review](trace-aware-review.md)

## I want to evaluate Ordin

- [Local integration evaluation and recorded reports](integration-evaluation.md)
- [Agent Safety Corpus v1 (0.4 development)](agent-safety-corpus.md)
- [Adapter conformance](integration-conformance.md)
- [Agent trajectory corpus](agent-trajectory-corpus.md)
- [Failure replay](failure-regressions.md)
- [Extended regression promotion](regression-promotion.md)
- [Local trace capture and reviewed promotion](trace-capture.md)
- [Safety benchmark and adversarial fuzzing](safety-benchmark.md)
- [Search quality benchmark](search-quality-benchmark.md)

The safety benchmark has separate hard regression gates for false allows, critical misses, false blocks, and weakened adversarial equivalents.

## I want to understand command discovery

- [Search quality benchmark](search-quality-benchmark.md)
- [Deterministic ranking](deterministic-ranking.md)
- [Availability and Linux platform signals](availability-and-platforms.md)
- [Optional semantic reranking](semantic-reranking.md)
- [Command packs](command-packs.md)

## I want to extend or contribute to Ordin

- [Development workflow](development-workflow.md)
- [Safety benchmark and adversarial fuzzing](safety-benchmark.md)
- [Generic action review and adapter contract](action-review.md)
- [Execution capability profiles and observations](execution-evidence.md)
- [Decision provenance and local audit evidence](audit-and-provenance.md)
- [Tool and MCP adapters](tool-and-mcp-adapters.md)
- [Declarative action policies](policies.md)
- [Temporal action policies](temporal-policies.md)
- [Command packs](command-packs.md)
- [Schema contracts](schema-contracts.md)
- [Releasing Ordin](releasing.md)
- [v0.4 release preparation notes](releases/v0.4.0.md)
- [Packaged pilot procedure and elapsed-time acceptance](release-pilot-0.4.md)
- [v0.3 post-release review and roadmap](post-release-0.3.md)
- [v0.3 release notes](releases/v0.3.0.md)
- [Security and threat model](threat-model.md)
- [Contributing guidelines](../CONTRIBUTING.md)

The local quality contract is:

```bash
python -m pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
pytest -q
```

The core design rule across safety layers is conservative composition: richer semantic, contextual, temporal, adapter, observed, provenance, or caller-owned policy evidence must not erase a known stronger safety requirement. Execution policy is applied separately by the caller or shell integration.
