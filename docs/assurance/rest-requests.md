# Exact REST request scope

`Ordin(rest_semantics=RestSemantics())` opts the protected host into deterministic
classification of `network.http.request`. Ordinary `Ordin()` keeps its existing
unsupported-action review. Proposal fields, profile JSON and imported authority
labels cannot turn this setting on. The host selects it in code/configuration,
alongside separately protected maxima and the approved profile.

The supported proposal contains `url`, an exact uppercase method, optional
`headers`, and optional typed JSON `body`. Supported methods are GET, HEAD,
OPTIONS, POST, PUT, PATCH and DELETE; the host may select a smaller tuple.
Literal HTTP/HTTPS host/port/path are checked by the existing endpoint parser.
Query/fragment delimiters, encoded/ambiguous path aliases, unknown fields,
duplicate case-insensitive header names, hop-by-hop overrides and raw credential
headers are unsupported. Bodies with non-JSON content types are unsupported.
This scope does not describe arbitrary raw HTTP, redirects, ambient credentials,
browser sessions or a server's application effects.

GET/HEAD/OPTIONS without a body are classified as reads; other shapes carry a
proposed upload/write effect and retain the baseline warning/approval behavior.
Classification is not a grant. The derived core v1 capability explicitly retains
`runtime_rest_request_commitment_required`. Its ordinary capability verifier and
legacy v2 request verifier cannot silently treat the missing exact scope as
verified.

`RestRequestAuthority` records scheme, endpoint, method, access, body presence and
the existing bounded typed-JSON SHA-256 commitment to the complete method/URL/
normalized-header/body packet. Header case/object order are neutral; values and
JSON types are bound, and an omitted body differs from null. The raw URL in the
commitment binds scheme and lexical spelling even where endpoint tuples match.
Body/header values do not appear in the authority record. `as_dict()` still
contains endpoint paths and is private serialization; public gate/example
reports use digests and coarse reasons.

`RestRequestBoundary` combines an independent host-owned capability maximum with
the allowed exact request declarations. `derive_rest_request_contract()` retains
the reviewed action's full capability requirements. The composite verifier
accounts for the REST commitment requirement and checks all remaining domains,
credentials, unknowns and disposition with the existing core verifier. Its
internal projected question is never returned as a grant. A matching data record
does not authenticate host scope, establish lifecycle or install enforcement.

The protected host can compose the invariant without deriving its maximum from
the submitted request:

```python
from ordin import AgentGate, Ordin
from ordin.assurance import AssuranceGate, HostRequestAuthority, RestSemantics

# actual approved_profile, source and rest_maximum come from protected host state
baseline = AgentGate(Ordin(rest_semantics=RestSemantics(("GET", "HEAD"))))
gate = AssuranceGate(baseline, approved_profile)
context = source.context(
    request_authorities=(HostRequestAuthority("task-rest", rest_maximum),)
)
result = gate.evaluate_action(proposed_action, host_context=context)
```

The approved profile selects `network_request_subset` with authority reference
`task-rest`. Missing authority stays inconclusive. A changed method/path/scheme,
header value or material JSON body cannot reuse the maximum or a previous review
binding. A matching POST/body commitment can satisfy the invariant while the
baseline still requires approval. Changing the REST semantic selection changes
session/gate configuration identity; existing history/reviews cannot transfer
under the new configuration.

The four independent schemas are REST semantics, authority, boundary and
contract. Published core v1/v2 request schemas remain unchanged. JSON round trips
are data-only; only `HostEvidenceSource.context()` supplies the protected host
scope consumed by the invariant. Simulation preserves the semantic selection as
an inert replay configuration and never activates a profile or sends a request.

Run the packaged offline example without a key or transport:

```bash
python -I -m ordin.assurance.rest_demo
```

It reviews an owned synthetic allowed GET and denies changed method/path/body
proposals, reporting that the old binding cannot be reused. Network/process
spies cover the example and installed-wheel smoke. Physical REST proxy/backend
enforcement, native child-grant forwarding and arbitrary raw HTTP remain outside
this tested SDK scope. The caller owns execution, must send the exact reviewed
request, and rechecks action/profile/session/policy/grant bindings immediately
before forwarding. No old receipt may approve changed wire data.
