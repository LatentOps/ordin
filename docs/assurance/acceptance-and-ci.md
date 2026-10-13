# Contractual acceptance fixtures and CI

The [fixed AT-01–AT-35 plan](../../benchmarks/assurance/v1/acceptance-plan.json)
links each minimum scenario to executable assertions. It is a regression plan
over owned synthetic sources, not an independently labeled effectiveness corpus.
The separate 24-case semantic workload remains provisional and ineligible for
broad effectiveness acceptance. Neither fixture count meets the requested
100 independently labeled harmful plus 100 benign controls.

Run the fixed plan from an installed core wheel and the independent optional
decision-model wheel. Only pytest/build tooling is needed; no Laya extra,
credentials, real scanner or hosted provider is installed. A fresh-wheel report
from `scripts/check_assurance_wheel.py` is a prerequisite:

```bash
python -I scripts/run_assurance_acceptance.py \
  --revision EXACT_40_CHARACTER_COMMIT \
  --wheel-check .assurance-work/candidate-wheel.json \
  --output .assurance-work/candidate-acceptance
```

Use a clean committed candidate and a new output directory. The runner rejects
source imports, mismatched source revisions and installed core/source bytes. It
executes the exact referenced test nodes without changing their assertions.
Observed gate calls record action/context/configuration/profile digests,
baseline/final dispositions, reason codes, invariant results and grant-use
outcomes when present. Artifact and typed-containment fixtures explicitly record
that no runtime gate review was observed. Default reports omit commands, paths,
source bodies, credentials and exception messages; detailed pytest/JUnit output
stays private in scratch storage.

Exit `0` means the selected fixtures passed and observation succeeded. It does
not mark overall acceptance complete: the report always retains
`overall_acceptance=incomplete`, all partial coverage and proof limits. Exit `1`
means a test, collection, coverage selection or observation failed. Setup errors
refuse execution rather than substituting a source checkout or weaker test.

Host-selected literal REST and exact typed JSON body/header scope now have
dedicated AT-07 assertions; ordinary default HTTP remains unregistered. Coverage
still open includes a real abstract-to-concrete solver
candidate, native database-delete integration, physical authorization/broker
receipts, general target-code fix verification and all standalone example audits.
Changed GraphQL/MCP requests, declared full-domain containment, synthetic host
correlation and policy replay have their own finite tested scopes.

The [offline CI workflow](../../.github/workflows/assurance.yml) adds Linux and
Windows/Python 3.10–3.13 Assurance fixtures and fresh-wheel smoke. Separate optional
jobs on Python 3.10/3.13 exercise predetermined model values, fake scanner
processes, saved artifacts and installed optional namespaces. The model job runs
the fixed minimum acceptance plan. Development tools use the existing hashed
baseline. Actions are pinned, checkout credentials are not persisted and default
permissions are read-only. The workflow contains no real-provider/scanner job,
upload, publication or enforcement installation.

Local workflow parsing/security checks do not establish successful remote CI.
The Assurance jobs preload their core and selected optional namespace from
the installed wheel before pytest can add checkout paths. The installed runner
rejects editable/source imports and audits every loaded module afterward for
source overlays. Core, optional, solver and kernel suites retain their existing
assertions and write JUnit results. Shared quality hooks also cover both optional
packages and the Assurance typed boundaries.

The existing full-suite, safety, trajectory, replay, integration, runtime,
OpenShell/native prover, packaging and exact release-candidate gates remain
mandatory. Their original thresholds, including the failed predeclared Assurance
latency budget, are unchanged. Use the [implementation ledger](implementation-report.md)
for actual revision/environment/results; use the [release gate](../release-candidate-gate.md)
for integration review and publication boundaries.
