# Ordin Assurance

Assurance is an optional, local security-assurance layer under construction on
`feat/ordin-assurance`. The default Ordin runtime is unchanged. The complete
requested system includes profiles, invariant review, simulation, safe
counterexamples, evidence graphs, delegation, offline scanner import, optional
models, validation and CLI examples. See the actual milestone state in
[the implementation report](implementation-report.md).

The implemented slices provide bounded immutable machine contracts, scoped
source inventory/threat-model drafts, protected profile selection and exact
restriction compilation. A conservative runtime wrapper is the next milestone.
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
and [the implementation report](implementation-report.md) for verified scope.
No scanner, model, network account or new mandatory dependency is needed to
use these records. No artifact executes actions or grants OS permissions.
