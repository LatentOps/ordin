# Ordin Assurance

Assurance is an optional, local security-assurance layer under construction on
`feat/ordin-assurance`. The default Ordin runtime is unchanged. The complete
requested system includes profiles, invariant review, simulation, safe
counterexamples, evidence graphs, delegation, offline scanner import, optional
models, validation and CLI examples. See the actual milestone state in
[the implementation report](implementation-report.md).

The implemented slices provide bounded immutable machine contracts, scoped
source inventory/threat-model drafts, protected profile selection and exact
restriction compilation, a conservative runtime invariant wrapper, and independent
policy simulation, bounded source-flow/attack-path analysis, protected delegation,
offline scanner import and optional semantic SDKs. Finding source review and
finite gate/policy-fix replay are available; target-code validation and integrated
release acceptance remain open.
For example, this creates validated profile **content**, without activating it:

```python
from ordin.assurance import RepositoryScope, SecurityProfile

content = SecurityProfile(
    profile_id="fixture",
    version="1",
    repository=RepositoryScope("fixture/repository", "snapshot-1"),
)
assert SecurityProfile.from_dict(content.as_dict()) == content
print(content.digest)
```

Loading arbitrary JSON cannot produce `ApprovedSecurityProfile`. Drafts are
always non-authoritative. Strong provenance and finding closure require a
separate protected host channel; serializing a trust label does not supply it.
These Python boundaries do not protect against malicious code inside the
trusted host process.

Read [machine contracts](contracts.md), [the baseline inventory](baseline-inventory.md),
the [profile lifecycle](profiles.md), [security/privacy](security-and-privacy.md),
the [invariant gate](invariants.md),
the [policy simulator](simulation.md),
the [bounded challengers](challengers.md),
the [host instruction/data origins](instruction-origins.md),
the [bounded attack paths and source-flow guards](attack-paths.md),
the [host delegation lifecycle](delegation.md),
the [offline Codex Security importer](codex-security-integration.md),
the [scoped finding and fix workflow](finding-validation.md),
the [saved external workflow claims](external-workflow-claims.md),
the [CLI/API reference](cli-and-api.md), [host adapter composition](adapter-composition.md),
the [acceptance fixtures and CI](acceptance-and-ci.md),
[the offline quickstart](../../examples/assurance/README.md),
and [the implementation report](implementation-report.md) for verified scope.
No scanner, model, network account or new mandatory dependency is needed to
use these records. No artifact executes actions or grants OS permissions.
