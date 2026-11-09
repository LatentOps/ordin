# Ordin Runtime naming and compatibility

Ordin Runtime is the project-owned optional adapter, compiler, policy management
and evidence tooling. Install `./integrations/runtime[yaml]`, import
`ordin_runtime`, and use `ordin-runtime`. Core and optional Swarm callers use
`runtime_backend.SwarmRuntimeBackend`. The demo is `scripts/run_runtime_demo.py`;
its current guide is [runtime-demo.md](runtime-demo.md).

The Python API now exports `OrdinRuntimeBackend`, `compile_runtime_policy`,
`RuntimeCLI`, `RuntimeCommandError`, `RuntimeProverResult`,
`verify_with_runtime_prover`, `prepare_runtime_apply`, `apply_runtime_policy`,
`parse_runtime_event`, `ingest_runtime_event`, `propose_runtime_delta`, and
`runtime_doctor`. The old distribution/import paths are replaced. The hidden
legacy `--openshell` executable option remains accepted; current help and examples
use `--runtime-executable`. Native test selection prefers `ORDIN_RUNTIME_PROVER`
and accepts the legacy `ORDIN_OPENSHELL_PROVER` variable as compatibility input.
The developer-experience evidence capture script advertises `--runtime-junit`;
the legacy `--openshell-junit` option is accepted without appearing in help.
Both select the same required runtime input, and ambiguous dual inputs refuse.
Existing report keys `openshell_gate` and `openshell_passed` remain compatible;
the migration neither rewrites archived reports nor changes their no-effect claims.

The verified engine is the pinned NVIDIA OpenShell upstream, revision
`6648bd0c290efbc41ba131ee9831ee45cd431f94`, build version `0.1.2`. This rename does
not claim authorship of that implementation or change its enforcement semantics.
The project-owned adapter version remains unchanged. The following literals are
retained intentionally:

| Literal/data | Why it remains |
| --- | --- |
| Native programs `openshell`, `openshell-prover`, supervisor/gateway/VM-driver names and exact version responses | The pinned binaries expose these verified interfaces. |
| Upstream `NVIDIA/OpenShell` URL, Rust crate/source paths, protobuf identifiers and `OPENSHELL_*` build variables | Build and source verification must describe the actual upstream implementation. |
| Published backend value `openshell`, `ordin.openshell_*` schema identifiers, `openshell_*` and `swarm.openshell_*` reason codes, existing report keys | Changing these would change stable wire data, policy/correlation digests or audit compatibility. They are protocol data, not current package or CLI names. |
| OCSF product `OpenShell Sandbox Supervisor`, vendor `OpenShell`, version `0.1.2` and `openshell-ocsf*.log*` | The collector must authenticate the actual upstream event format and log selection. |
| Denied hostname `host.openshell.internal` | Renaming a restricted destination could widen the accepted network scope. |
| `runtime/patches/request-authority-v1.patch` and `ordin_runtime/runtime_identity.json` contents | Exact audited patch bytes, hashes, source identities and notices are unchanged. Only their containing project paths moved. |
| Archived evidence and its original filenames under `docs/reports/` and `docs/assurance/evidence/`, plus `docs/assurance/implementation-report.md` and `docs/runtime-enforcement-acceptance.md` | These are historical observations, not newly generated or re-signed proof for the renamed code. |
| Historical implementation-request document name in the design note | It identifies the original design input rather than a live module, directory or command. |

The adapter still refuses unknown or widened authority, requires exact operator
approval/currentness for management apply, preserves UID/resource/readiness
requirements, and keeps compile/validate free of execution. No runtime version,
tag, release, paid call, model download or required CI job display name changes
as part of this migration. Native and installed-wheel qualification must be run
against the final integrated commit; the archived reports do not provide it.
