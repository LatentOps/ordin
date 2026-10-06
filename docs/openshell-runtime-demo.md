# Actual OpenShell runtime demo

The [recorded report](reports/openshell-runtime-demo.json) comes from OpenShell
0.1.2's VM driver under KVM, with guest Linux 6.12.76. The host WSL2 kernel is
5.15.167.4. Docker sandbox startup on that host failed closed because required
Landlock `Refer`/`Truncate` rights were unavailable. The VM route retained the
hard-requirement policy and supplied a compatible guest kernel; host enforcement
was not relaxed.

The actual probes established:

- The exact public GitHub issue GET returned the requested issue body.
- POST to the same path returned OpenShell's structured `policy_denied` response.
- An unrelated host was denied, with a matching backend enforcement event.
- Reading the fixture succeeded. Its POSIX mode was `0666`, with owner and
  workload EUID both 1000; a control write under `/tmp` succeeded while the
  protected write was denied.
- Three real structured network events passed exact private correlation and
  entered the original Ordin session. A later review retained their provenance.
- The host-controlled filesystem probe entered a separate session as
  `backend_observed`. The pinned backend lacks a native filesystem OCSF class;
  this does not claim one or label the host probe cryptographic attestation.
  The read-only `cat` baseline and negative Python probe are distinct reviewed
  invocations; the denial binds the exact executed Python argv and its original
  contract. Python code semantics remain explicitly unknown. The controlled
  fixture does not convert that diagnostic contract into a grant.
- Effective policy, loaded revision, and workload admission agreed; canonical
  policy digest matched the compiled contract without added authority.

The [actual apply report](reports/openshell-runtime-apply.json) also records a
named policy revision 1-to-2 update with identical authority and a new rule
identifier. An unapproved call returned `requires_approval`; the trusted host
test fixture then supplied the exact approval request. Core boundary validation,
the real OpenShell prover, loaded-policy/admission readback, and two hash-chained
operator receipts passed. Applying the policy executed no workload action.
The fixture approval demonstrates the operator API; it is not a production
human-approval system.

The example is an explicit caller program, separate from execution-free Ordin:

```sh
python scripts/run_openshell_runtime_demo.py \
    --openshell /path/to/openshell \
    --gateway-endpoint http://127.0.0.1:18780 \
    --sandbox ordin-vm-get-e2e \
    --filesystem-sandbox ordin-vm-fs-e2e \
    --correlation-db private/demo-correlation.db \
    --json-out runtime-demo.json
```

Configure existing disposable sandboxes beforehand, using a compatible runtime,
the exact GET host/path/method and binary rule, non-root workload identity, and
explicit reviewed deployment requirements. The filesystem fixture must be
POSIX-writable to the workload user while its runtime path policy is read-only.
The [fixture image](../examples/runtime-enforcement/Dockerfile) and
[advisory policy generator](../examples/runtime-enforcement/prepare.py) provide
the non-secret setup used by this workload:

```sh
python examples/runtime-enforcement/prepare.py > demo-policy.json
docker build -t ordin-runtime-demo:0.1.2 examples/runtime-enforcement
openshell --gateway-endpoint http://127.0.0.1:18780 sandbox create \
    --name ordin-vm-get-e2e --from ordin-runtime-demo:0.1.2 \
    --policy demo-policy.json --no-auto-providers --detach --no-tty \
    -- /usr/bin/sleep infinity
openshell --gateway-endpoint http://127.0.0.1:18780 sandbox create \
    --name ordin-vm-fs-e2e --from ordin-runtime-demo:0.1.2 \
    --policy demo-policy.json --no-auto-providers --detach --no-tty \
    -- /usr/bin/sleep infinity
openshell --gateway-endpoint http://127.0.0.1:18780 settings set \
    ordin-vm-get-e2e --key ocsf_json_enabled --value true
```

These are explicit operator setup commands against a preconfigured gateway;
they are outside Ordin core. The fixture image needs a compatible OpenShell
driver/kernel. The generated startup paths are declared host requirements and
must be reviewed for the deployment; they are not inferred from curl's network
semantics.
Enable sandbox setting `ocsf_json_enabled=true` so the explicitly selected
runtime-owned log contains JSON events. Use a private directory for correlation
and serialize sandbox use during the collector's test window.

The script never starts/creates/retries a sandbox, grants policy, attaches
credential providers, or captures response bodies/commands in its report. It
confirms the exact read-only network/filesystem fixtures before probes,
reviews the exact caller probe argv, checks readback, runs deliberate positive
and negative test requests, and returns success only when all assertions pass.
The closed-loop action intent is inspection of issue 37. `gh issue view` itself
uses GraphQL rather than the REST GET assumed by the original plan; unsupported
GraphQL restrictions are never disguised as GET or downgraded to raw TCP.

These observations establish this workload on the recorded runtime. They do
not establish universal action safety, remote attestation, resistance to a
compromised host/supervisor, or an atomic policy compare-and-swap.
