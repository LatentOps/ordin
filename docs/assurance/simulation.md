# Policy simulation

`simulate_policy_change` runs two independent `IntegrationSession` sets over a
`FrozenCorpus`. It calls the existing core and `AssuranceGate`, retains refused
proposals in each arm's bounded history, and separates principals and epochs.
Actions, context, contract checks and caller observations are detached before
replay. Corpus manifests bind mandatory case contents and versions; the optional
expected corpus digest also binds ordering and metadata.

No fixture command is executed. No provider, scanner, approval, runtime evidence
or delegation grant is created. Observations use the existing caller-asserted
format. An observation following a refused proposal is withheld and reported as
a coverage gap. Initial histories are replayed as proposals; they supply no
execution evidence. Parsed trajectories and sanitized trace candidates have
adapters. Fixture semantics must be explicitly included in both policy arms;
the adapters cannot silently install a tool registry.

```python
from ordin import ActionEnvelope
from ordin.assurance import FrozenCase, FrozenCorpus, SimulationPolicy, simulate_policy_change

corpus = FrozenCorpus.synthetic((FrozenCase(
    "read-only", ActionEnvelope.shell("git status --short"),
    expected="execute", label="benign",
),))
policy = SimulationPolicy()
report = simulate_policy_change(
    policy, policy, corpus,
    baseline_revision="fixture-v1", candidate_revision="fixture-v1",
    expected_corpus_digest=corpus.digest,
)
assert report.activation_safe
```

The JSON report retains core and final dispositions, new denials/escalations/
execution, unresolved cases, effect and temporal changes, capability digests,
policy/profile/selection/corpus/action digests, revision and environment. Counts
of critical fixtures caught/missed describe declared fixture expectations; they
do not confirm vulnerabilities. Unknown fixtures do not count as caught.
Coverage counts every action kind. Core timings measure the existing gate;
wrapper timings include local Assurance and session bookkeeping. Gate construction,
report formatting and capability-diff derivation are outside these timings.
Baseline runs first, so cache and host effects can bias comparisons. Timing
values vary; ordered inputs and decisions are reproducible.

Authority comparison uses the full existing capability subset verifier and
retains exact protocol request/grant identities. A changed arbitrary policy or
profile whose containment cannot be proved is `unknown`. Unsupported domains
stay explicit. Declared maxima describe policy data; they do not establish OS
enforcement. JSON cannot load an approved profile handle. Host callers may pass
an already protected `ApprovedSecurityProfile` through the SDK.

`activation_safe` is an advisory change guard. It is false for newly executable
actions, critical downgrades/misses, widening/unproved authority, missing or
unresolved fixtures, unknown permission metadata, or unspecified revisions.
It never installs a policy or authorizes an action. `source_permissions` is
caller metadata about the corpus; it is not an authenticated permission grant.
Public fixture IDs, revisions and labels must be suitable for disclosure.
Default reports omit fixture arguments, commands, observation bodies and source
paths, and include only hashes, stable codes and declared public identifiers.

The separate CLI accepts the requested command forms, with explicit revision
flags for a passing release check:

```console
ordin-assure profile validate ./security-profile.json
ordin-assure policy simulate --baseline ./old-policy.json --candidate ./new-policy.json --corpus ./corpus.json --baseline-revision fixture-v1 --candidate-revision fixture-v2
ordin-assure policy diff --baseline ./a.json --candidate ./b.json
```

`--report ./new-report.json` explicitly creates a new file; an existing file is
refused. Default operation writes only JSON to stdout. Input is local bounded
JSON, with duplicate/nonfinite/control/depth checks and no links or hardlinks.
Policy and corpus packets use `ordin.assurance_replay_policy.v1` and
`ordin.assurance_replay_corpus.v1`. Their complete shapes are demonstrated in
[the frozen fixture inputs](../../benchmarks/assurance/v1/simulation-corpus.json)
and produced by `python -m scripts.freeze_assurance_simulation`. The SDK accepts
existing `Ordin` configuration and freezes its core policy/temporal/semantic
settings; custom gates, audit sinks and traces are refused.

Exit codes are `0` for a complete passing guard, `1` for a detected security
regression, and `2` for partial/unproved/malformed results. A detected regression
takes precedence over a partial result. Ordinary `ordin check` is unchanged.

The 22-case synthetic corpus covers 11 scenario families with benign and
adversarial counterparts. Delegation lifecycle and model uncertainty fixtures
explicitly remain partial until M7/M9 supply their integrations. Untrusted MCP
tools remain unknown. This corpus is a simulator smoke corpus, not the later
100-adversarial/100-benign effectiveness benchmark or real scan evidence.

## Optional semantic-policy replay

After installing the independent `ordin-decision-models` wheel, run:

```console
python -I -m ordin_decision_models.simulation_demo
```

`simulate_semantic_policy_change` compares two `SemanticReplayPolicy` selections
over the same `FrozenCorpus`. It reuses the deterministic replay guard and runs
the actual semantic router/fusion through independent `IntegrationSession`
instances for each arm, principal and epoch. Rejected proposals remain in history;
their caller observations are withheld. One fresh router budget spans all sessions
within each arm, so switching identity cannot replenish the replay call budget.
Initial history proposals also consume that budget when they require inspection.

This driver deliberately accepts synthetic fixtures and the project's fixed
offline mock only. Synthetic task selections are explicit, bounded context;
corpus labels never reach the mock. Fixture JSON cannot choose a provider,
endpoint, checkpoint, executable or callback. Permission metadata remains a
caller claim and creates no real operator consent, grant or runtime observation.
Hosted/local real-provider evaluation remains a separate opt-in workflow.

The additive `assurance-semantic-simulation.v1` report retains the deterministic
core and combined final decisions, configuration/corpus/revision digests,
reason codes, benign friction, critical misses, unresolved cases and authority
comparison. It separates total/core/wrapper timings from recorded mock inference
latencies and call counts. Wrapper time includes privacy processing, routing and
waits. Timeout evidence can lack an inference duration; zero samples records
that no model was called. Task text and commands are omitted from public output;
configuration hashes are commitments, not encryption.

Removing enforced semantic scrutiny is reported as widening even when the
selected cases happen not to change. Changed enforced configurations have
unknown containment; fixture passes alone cannot prove global containment.
Missing required context, provider outages, invalid responses, uncertainty,
budget exhaustion and preexisting proof gaps prevent a complete passing guard.
The demo's deliberately high risk prediction on a benign command demonstrates
false escalation cost; it is not independent model effectiveness evidence.
