# Packaged pilot for v0.4

The pilot runs a fixed synthetic two-agent workload against an exact installed
candidate. It uses no production repository, external service, real API key or
model provider. Its reports describe observations; they cannot approve another
action or authorize a production rollout.

A short engineering probe and a multi-day operator pilot answer different
questions. Completing the engineering commands below does not establish that
three to seven days elapsed. Public release acceptance remains pending until the
actual requested window completes and a human reviews that evidence and the
intended deployment scope.

## Inputs and preparation

Use a clean checkout at an independently selected full commit and tree, and the
five-package candidate bundle built from that same checkout. The bundle contains
the core, Swarm, Runtime, Security and Decision Models wheel/sdist pairs, release
metadata, SBOM and hashes. No public prerelease tag is required for this exact-SHA
engineering step. Publication remains a separate final-version/tag operation.

Create an isolated environment and install the bundle's core and Swarm wheels,
plus the pinned pytest/support tools from the reviewed development lock. Keep
optional model providers and production credentials out of this environment.
The harness does not download, build or install dependencies and does not accept
arbitrary test selectors or imported result JSON. Use the supported Linux kernel
and privileged setup already required by the owned-worker acceptance lane for
the full workload. A Windows run can exercise the explicitly selected portable
subset; it cannot establish Linux or Windows process confinement.

The release verifier checks all five package pairs against the selected source.
The pilot additionally compares every installed core/Swarm payload file with its
verified wheel before runtime imports, rejects source/editable overlays, and
uses a fresh bytecode-cache location. A fully compromised interpreter or owner
is outside this evidence boundary. Run the exact-source helper with that
environment's Python using `-I -B`, from outside the checkout.

## Short engineering probe

Replace the absolute paths and full Git identifiers with the selected candidate:

```sh
/ABS/ENV/bin/python -I -B /ABS/SOURCE/scripts/run_release_pilot.py \
  --bundle /ABS/DIST --output /ABS/NEW-ENGINEERING-OUTPUT \
  --revision FULL_COMMIT_SHA --tree FULL_TREE_SHA \
  --owned-fixture --mode engineering --cycles 2
```

On Windows, use the environment's `Scripts/python.exe` and add `--portable-only`.
The default is two immediate bounded cycles. Engineering mode permits one to
sixteen cycles with an optional interval of zero to sixty seconds. It always
records `elapsed_pilot_window_satisfied: false`, regardless of imported files or
clock values. There is no multi-day CI job or short-run substitute for elapsed
pilot evidence.

Every cycle runs the same ten owned synthetic protocol/accounting checks:
authenticated two-agent dispatch and shared limits; takeover/epoch fencing;
revocation surviving restart; injected lost-forward acknowledgements retaining
holds; changed-epoch recovery refusal; rejection of JSON resume claims; and
durable uncertain/consumed budgets. These tests exercise real local TLS and
durable stores. The lost-ack cases are deliberate fault injection, not evidence
that a real external transaction happened or that JSON can authorize recovery.

The full Linux cycle also runs the installed managed-host evaluator's fixed
read, handoff, exact approved write and shutdown workflow. A supplemental fixed
host workflow exercises an authenticated denial, connection-bound cancellation,
native revocation, shutdown, restart at a new epoch, rejection of the original
client handle, and retention of existing durable consumption. Original objects
remain owned until cleanup succeeds. Ordinary client-process confinement is
not claimed by these host-side tool checks.

## Explicit three-to-seven-day pilot

Only after the engineering probe succeeds, a human operator can start a full
Linux pilot with an explicit duration. This command requests three real days,
with at most one cycle starting per fifteen-minute interval:

```sh
/ABS/ENV/bin/python -I -B /ABS/SOURCE/scripts/run_release_pilot.py \
  --bundle /ABS/DIST --output /ABS/NEW-PILOT-OUTPUT \
  --revision FULL_COMMIT_SHA --tree FULL_TREE_SHA \
  --owned-fixture --mode pilot --duration-seconds 259200 \
  --interval-seconds 900
```

Pilot mode accepts 259200 through 604800 seconds and intervals of 300 through
3600 seconds. It requires the full Linux workload. Both monotonic elapsed time
and the recorded UTC start/end difference must meet the requested duration;
all completed cycles must pass, with at least two cycles. Failure, cancellation,
clock rollback or incomplete cleanup prevents window qualification. A stopped
process is not resumed from its JSON. A new invocation starts a new measured
window and fresh synthetic scopes. Budget continuity is checked within each
owned restart scenario, not by merging unrelated pilot runs or resetting a
production accounting domain.

## Bounds, cleanup and interpretation

The scheduler caps a seven-day run at 2017 cycles, never runs cycles concurrently,
and checks a sixty-second controller-CPU budget per cycle. Fixed workers retain
their original kernel, payload, process and timeout limits. The fixture archive
is bounded by the existing release collector; cycle storage is checked against
128 MiB. Only one cycle installation is retained at a time and is removed after
its resources close. The compact cycle journal is capped at 4 MiB; output capture
is capped at 1 MiB. The controller's CPU counter does not include child CPU; it
does not replace original worker resource controls or an operator disk quota.

`SIGINT`/`SIGTERM` interrupt new work and unwind original resources. If a host
reports incomplete cleanup, the foreground controller retains that exact retry
owner and retries cleanup only. It does not repeat the workload, delete unresolved
installation data, refund an uncertain hold, or report success. Keep that
controller alive until cleanup completes. Unresolved cleanup is an acceptance
failure requiring operator attention; forcibly killing the controller is not
evidence of successful cleanup.

`pilot.json` records the actual UTC start/end, monotonic and UTC elapsed times,
selected revision/tree, bundle/wheel hashes, Python/platform, requested scope,
counts, status and journal digest. `cycles.jsonl` contains bounded aggregate
cycle outcomes and diagnostic hashes, without tool bodies, private keys or raw
tracebacks. Portable counts and actual Linux host cases remain distinct.

Even a successfully elapsed window leaves `operator_acceptance` pending and
`production_rollout_authorized` false. Human review must consider missing
platforms, workload relevance, false blocks/allows, observed uncertainty,
shutdown and recovery behavior, and the intended operational limits. Neither
this document nor a passing synthetic pilot establishes universal agent safety.
