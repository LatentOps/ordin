# Verify and try a v0.4 artifact bundle

This procedure applies to an exact-SHA candidate bundle or, after publication,
the immutable v0.4.0 release assets. These instructions do not assert that a
public v0.4.0 release already exists. Use Python 3.10–3.13 in a new environment.
The installation commands below target a prepared final-version candidate with
core and Swarm metadata at `0.4.0`; earlier development bundles use their actual
recorded package versions.
The portable fixture needs no model, provider account or credential.
Replace `/absolute/...` with an actual absolute local directory; on Windows use
an absolute drive path such as `C:\verified-bundle`.

Obtain the complete bundle and its source SHA through the release review. For
a hosted bundle, verify the GitHub workflow attestation and `SHA256SUMS` using
[the release verification procedure](releasing.md#verify-artifact-identity).
An exact-source local candidate has no hosted attestation until that workflow
has actually run. From its clean matching checkout, validate the whole bundle:

```console
python scripts/release_integrity.py verify --bundle --dist /absolute/verified-bundle --revision TRUSTED_FULL_COMMIT_SHA
```

The command above verifies an untagged candidate whose manifest has `tag: null`.
For the published bundle, supply the independently trusted `--tag v0.4.0` as
well; its manifest must match that exact tag and revision.
Do not replace the trusted SHA with a moving branch or treat checksums alone as
proof of the origin of downloaded bytes.

Create and activate a fresh virtual environment, then install only from that
verified local bundle:

```console
python -m venv .ordin-v040
# POSIX: source .ordin-v040/bin/activate
# PowerShell: .ordin-v040\Scripts\Activate.ps1
python -m pip install --no-index --find-links /absolute/verified-bundle ordin==0.4.0 ordin-swarm==0.4.0
python -m pip check
ordin doctor --json
ordin-swarm-adapter status --framework custom
python -I -m ordin_swarm.quickstart
```

The custom two-agent report identifies synthetic labels, callback mediation
and `physical_enforcement: false`. It reviews proposals, performs its permitted
local read/private handoff, and refuses mediated egress/child-creation calls.
It does not measure a hosted model, start a production daemon or establish OS
confinement. Run it as its own process; see the [fixture boundaries](swarm/quickstart.md).

The bundle also contains the independently versioned optional packages. Install
them explicitly only when needed, from the same verified directory:

```console
python -m pip install --no-index --find-links /absolute/verified-bundle ordin-runtime==0.1.0 ordin-security==0.1.0 ordin-decision-models==0.1.0
python -m pip check
ordin-runtime --help
ordin security --help
```

These base installs do not download SDK extras, a solver, the native prover, a
model or service credentials. Required optional tools must be separately
provisioned and qualified. CrewAI remains disabled by quarantine.

For supported Linux x86-64 physical worker evidence, use the separate
`python -I -m ordin_swarm.owned_demo --owned-fixture` procedure after checking
its kernel and privilege requirements. Windows portable fixtures do not provide
Windows kernel protection. Actual service initialization needs a dedicated
private workspace, fresh private PKI and an explicit profile; follow the
[managed host guide](swarm/managed-tool-host.md), not the synthetic fixture keys.

Before adoption, read the [v0.4 contract and rollback policy](public-compatibility-0.4.md)
and complete the [packaged pilot procedure](release-pilot-0.4.md). Retain actual
elapsed-time evidence and operator acceptance separately from engineering
checks; a finite passing fixture cannot approve a production rollout.
