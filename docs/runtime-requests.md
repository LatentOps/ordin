# GraphQL and MCP request restrictions

`ordin.runtime_requests` adds immutable `ProtocolRequestCapability`,
`RuntimeRequestContract`, `RuntimeRequestBoundary`, and
`RequestVerificationResult` beside the unchanged capability/boundary v1 formats.
The request artifact embeds the original action-bound capability and hashes all
request restrictions into `request_contract_id`. The compiled plan retains that
artifact and its digest; changing either the scope or action invalidates it.

GraphQL permissions describe an exact endpoint/path, operation type, operation
name, and allowed root-field set. MCP permissions describe an exact endpoint,
trusted logical server binding, method, tool for `tools/call`, and protocol
revision set. Empty/wildcard fields and unknown revisions are rejected. Tool
names identify requested permissions; they do not establish trusted semantics.
MCP derivation still requires exact registered tool semantics and a host-owned
server/transport declaration.

The deterministic `network.graphql.request` adapter accepts only named, flat
`query` or `mutation` operations with literal field identifiers. Variables,
arguments, aliases, directives, fragments, nested selections, batches and
subscriptions stay unmodeled. These permissions do not pin query text or
application-specific argument values. Requests requiring finer constraints
retain `requires_argument_constraints=true` and cannot compile. In particular,
`gh issue view` still cannot be represented as the plan's assumed REST GET or
an exact issue/argument-scoped GraphQL grant.

```python
from ordin import ActionEnvelope, Ordin
from ordin.runtime_requests import derive_runtime_request_contract
from ordin.runtime_requirements import RuntimeRequirementProfile

# Add the deployment's reviewed loader/filesystem paths separately.
profile = RuntimeRequirementProfile(
    "client", client_executables=("/usr/bin/curl",), spawn_children=True,
    mcp_endpoints={"monitor": "https://mcp.example.com/mcp"},
)
review = Ordin(runtime_requirements=profile).review_action(ActionEnvelope(
    "network", "graphql.request",
    {"url": "https://api.example.com/graphql",
     "query": "query InspectStatus { status version }"},
    action_id="inspect-status",
))
request = derive_runtime_request_contract(review)
```

The profile supplies physical client identity and MCP transport facts, without
changing predicted effects or decisions. Defaults preserve old profile/session
identities. Without declared filesystem/process requirements, compilation
continues to fail closed. Nonempty MCP tool arguments require argument
constraints and are unsupported by this compiler; argument values never enter
the request artifact.

`verify_runtime_request_capability` verifies every original capability domain
and then the request-specific scope. Transport bounds must agree with declared
protocol/endpoint/path scope. GraphQL operation/name equality and field subsets,
and MCP server/method/tool equality and version subsets, are checked separately.
Opaque unmapped identities and contradictory bounds return non-success. Its
additional `requests` coverage flag does not alter the original verification
result's six-domain contract.

```sh
ordin-openshell derive-requests --review review.json
ordin-openshell compile-requests --request-contract requests.json \
    --uid 1000 --gid 1000 --output policy.json
ordin-openshell verify-requests --request-contract requests.json \
    --request-boundary request-boundary.json
ordin-openshell apply --sandbox named-demo --contract capability.json \
    --request-contract requests.json --request-boundary request-boundary.json \
    --policy policy.json --uid 1000 --gid 1000 --audit private/apply.jsonl
```

Protocol apply requires a successful request boundary, exact approval, unchanged
startup controls, and verified loaded-policy/admission readback. The ordinary
contract input must equal the request artifact's embedded capability. It never
executes or retries an action. Shadow cases may supply `request_contract` and
`request_boundary`; network coverage then includes the request checks. Generic
HTTP events lack GraphQL operation/field and MCP method/tool facts, so their
request-level shadow comparison remains inconclusive rather than inventing
those facts from the review.

The pinned [OpenShell 0.1.2 network model](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/how-it-works/policies/network-rules.mdx)
supports these enforcement rules. Its [standalone prover](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-prover/src/containment.rs)
models only TCP and REST. Supplying a backend prover boundary therefore returns
`unsupported` for GraphQL/MCP and refuses apply. Local request-boundary checks
are distinctly labeled; they are not an OpenShell prover result. Credentialed
protocol policies, private-address expansion, and mixed MCP/non-MCP endpoints
on one host/port are also rejected.

The [recorded VM probes](reports/runtime-protocol-enforcement.json) verified
four GraphQL cases (forwarded query; denied mutation, field expansion and
operation-name change) and three MCP cases (forwarded allowed tool; denied
another tool and method). Effective, loaded and admitted policies matched their
compiled digests. The public HTTP echo service received only fixed non-secret
test payloads. These are request-enforcement probes, not claims that an
application GraphQL query or MCP tool executed successfully.

The runtime accepts a single-element `any` matcher for an exact MCP tool; this
is the supported emitted representation. Its readback `tool` alias is normalized
to the equivalent canonical `params.name` selector. Capability and metadata
contracts retain their ten-level bound; nested policy selectors have an
explicit twelve-level policy bound, and wrapped management responses fourteen.
All retain collection/text/byte bounds. No broader tool matcher is emitted.
