# Optional OCSF finding export

`ordin_openshell.ocsf_export` emits deterministic OCSF 1.8.0 Detection Findings
for blocked actions, security-policy approval requests, trajectory bypass
patterns, capability/request boundary exceedance, compiler widening rejection,
and runtime correlation failures. It is a pure optional API with explicit UTC
millisecond timestamps, no required OCSF/YAML library, network call or telemetry.

The exporter follows the primary [Detection Finding](https://github.com/ocsf/ocsf-schema/blob/v1.8.0/events/findings/detection_finding.json),
[Finding](https://github.com/ocsf/ocsf-schema/blob/v1.8.0/events/findings/finding.json),
and [Finding Information](https://github.com/ocsf/ocsf-schema/blob/v1.8.0/objects/finding_info.json)
definitions: category 2, class 2004, Create activity 1, type 200401, product
Ordin/LatentOps and the security-control profile. Finding identity binds the
source digest; event identity also binds the explicit time.

Commands, arguments, human reasons, plaintext resource names/IDs, runtime
payloads and credentials are omitted. The `unmapped.ordin` namespace contains
fixed finding kinds and integrity digests. Allowed actions and ordinary
unclassified `ask` reviews do not automatically become security alerts.

```sh
ordin-openshell export-ocsf --review review.json --time-ms 1791280000000
ordin-openshell export-ocsf --boundary-result verification.json \
    --compilation-result compilation.json --correlation-result correlation.json \
    --time-ms 1791280000000
```

The direct APIs are `export_review_findings`, `export_boundary_findings`,
`export_compiler_findings`, and `export_correlation_findings`. Output is portable
finding data, not runtime evidence or an approval. It does not label semantic
decisions `backend_enforced`, replace the local hash-chained audit, authenticate
the event producer, upload a transcript or configure a SIEM. The OpenShell event
ingester intentionally refuses these Ordin findings as native OpenShell runtime
observations.
