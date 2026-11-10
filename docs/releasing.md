# Releasing Ordin

Ordin releases are distributed through GitHub for now. A release consists of an immutable version tag plus validated wheel and source-distribution assets attached to the corresponding GitHub Release.

No package-index account, publishing token, or external registry is required.

## Version lifecycle

Published package versions are immutable identifiers. Never build new source under a version that has already been released.

The expected lifecycle is:

1. normal development uses the next PEP 440 development version, such as `0.4.0.dev0`;
2. a release preparation PR changes the matching core and Swarm declarations to the exact final version, such as `0.4.0`;
3. the full merge gate passes and the version PR is merged to `main`;
4. the packaged pilot completes its actual elapsed window, operator acceptance is retained, and the matching `v0.4.0` tag is created;
5. the release workflow validates, builds, smoke-tests, and attaches the exact artifacts to a GitHub Release;
6. immediately after the release, core and Swarm advance to the next unique development version, such as `0.5.0.dev0`.

A published version must never be reused for different package contents. This
applies independently to `ordin-runtime`, `ordin-security` and
`ordin-decision-models`, whose versions are currently `0.1.0`: a future payload
change requires that package's own new version even if core follows a different
version line. A bundle must not silently replace a previously published
optional-package payload under an unchanged version.

Update the version in both:

- `pyproject.toml` -> `project.version`
- `ordin/__init__.py` -> `__version__`

Also update the Swarm distribution/runtime declarations together and qualify
its core dependency bound. Optional package versions and their core bounds are
reviewed explicitly rather than inferred from the repository's tag.

Tests require the installed distribution metadata and runtime version to match.

## Preparing a final release

First complete the [exact release-candidate gate](release-candidate-gate.md)
and record its successful source SHA, CI and attestation evidence. A final
version change requires its own full gate afterward.

Change the development version to the exact final version in both version declarations, then run the normal local gate:

```bash
pre-commit run --all-files
pytest -q
python -m build
python -m twine check dist/*
```

Open a focused release-version PR and merge only after the complete CI matrix passes.

For the prepared final version, build the complete five-package candidate into
a fresh directory outside the clean exact-source checkout:

```console
python scripts/build_release_bundle.py --dist /absolute/new-candidate-bundle --revision TRUSTED_FULL_COMMIT_SHA --tag v0.4.0
python scripts/release_integrity.py verify --bundle --dist /absolute/new-candidate-bundle --revision TRUSTED_FULL_COMMIT_SHA --tag v0.4.0
```

These arguments bind the candidate to its actual source and intended final
version. They do not publish a tag or complete acceptance. Use the builder's
actual development-version arguments when validating earlier development
source; do not relabel it as final-version bytes.

Complete the [packaged pilot procedure](release-pilot-0.4.md), retain its actual
elapsed duration and operator decision, and keep publication held until that
acceptance is complete. An exact-SHA candidate bundle can be tested without
creating a public release. Short engineering checks are a different evidence
class; they cannot be backdated into the pilot window.

Then create the matching tag. For the qualified final version `0.4.0`:

```bash
git tag v0.4.0
git push origin v0.4.0
```

The release workflow refuses a tag that does not exactly equal `v<project.version>` and refuses a mismatch between distribution and runtime versions. Published tags must use a final `X.Y.Z` version; development versions can be validated through `workflow_dispatch` without publishing.

## Release workflow

Every `v*` tag:

1. validates version/tag consistency;
2. builds wheel and source distribution;
3. runs Twine metadata validation;
4. installs the built wheel into a fresh virtual environment;
5. runs installed `ordin doctor`, search, isolated Python API/version checks, adapter conformance, a Claude Code hook request, and the MCP entry point;
6. uploads the validated distributions as a workflow artifact;
7. creates the matching GitHub Release and attaches the exact validated wheel and source distribution.

The workflow refuses to replace an already-existing GitHub Release under the same tag. Published release assets are treated as immutable. Wait for every maintained CI check on the exact merged `main` commit before creating the tag; publication validates those checks again and requires the tagged commit to belong to `main`.

Publication requires all 44 maintained main jobs, bound to the latest exact-source
execution of their own workflow and GitHub Actions check suite. The release,
offline Assurance and native runtime workflows require completed manual runs on
`main`; the tag's own build/attest/publish jobs cannot supply that qualification.
Only the API-verified current tag attempt's three release jobs may still be in
progress during their own integrity checks. Their completed failures, new failing
or pending checks and commit statuses still block publication. Prior run attempts
are superseded only by a verified later execution in the same workflow scope.
Partial reruns retain untouched jobs: the latest verified result for each logical
job replaces only that job's earlier attempts, not the entire run's job set.
Run qualification is ordered by the start of the API-verified specific attempt,
so a newer retry of an older run ID cannot hide a failure before jobs start.
An older attempt's late cancellation does not supersede a later successful start;
missing, mismatched or ambiguous execution chronology blocks publication.
The PR-only Dependency review and Advanced Security CodeQL aggregate are not
required main successes. Main requires its own CodeQL Python job and processed
Python analysis for the exact source/ref/workflow, without an error or warning.
The two `Protected execution Python 3.10` and `3.13` jobs run required actual
kernel fixtures under controlled root privileges on Ubuntu. They build fresh
core/Swarm wheels, compare the installed runtime modules and schemas with the
exact checkout, and execute the agent/private-channel and fixed-pytest positives
outside that checkout. Fourteen named positives also require actual catalogue
build/load, pinned framework selection, private scratch logging, aggregate
custody, shared human-approved writes, and both ordinary and protected workflow
variants. The fresh installed console script and module must both run; the
console metadata must point to the original cleanup entrypoint. Tracked helper
and fixture trees are copied without source packages. Missing or skipped
required positives, failed cases, and unhandled thread errors fail qualification.
Catalogue restart checks revalidate the same immutable interpreter/tree without
executing project code or rebuilding a missing or changed snapshot. The complete
process fixture also exercises watchdog-start failures and retained cleanup.
Ordinary unsupported-platform skips cannot replace this evidence. The fixtures
use namespace, chroot, Landlock, seccomp, identity and bounded scratch controls.
Repository test counts and diagnostics remain data, not execution permits.
Only the verified main Dependency review and manual-release Publish GitHub
Release jobs may be skipped.

`workflow_dispatch` can exercise build and validation without creating a release.

PRs also run the release build and integrity checks with read permissions.
Manual validation can attest development artifacts; only tag pushes publish a
release. PRs cannot attest or publish. The
release build uses the pinned tools in `requirements/release.txt` without a
second isolated backend environment, so its recorded build inventory includes
the backend actually used. Transitive tools remain dependency-resolved and are
recorded in the SBOM; this is not a reproducible-build guarantee.

## Verify artifact identity

Starting with the next release, the attached assets include:

- tested wheel/source pairs for core, Swarm, Runtime, Security and decision models;
- `SHA256SUMS` covering every distribution, `release.json`, and `sbom.cdx.json`;
- `release.json`, binding package/runtime versions and artifact hashes to the source commit and tag;
- a CycloneDX 1.6 SBOM describing the bundle artifacts and observed build environment;
- `provenance.sigstore.json`, the GitHub attestation verification bundle.

The v0.4 bundle records the identity of each independently versioned package.
The SBOM marks build-environment components as excluded from the core runtime.
It does not claim that optional semantic extras or arbitrary downstream
environments were installed or inventoried. Checksums detect changed bytes;
attestation verification establishes which workflow/source identity vouched
for those bytes. Neither proves the source is free of vulnerabilities.

After downloading all assets into a new directory, verify them against the
commit you independently trust for the release:

```bash
gh attestation verify SHA256SUMS --repo LatentOps/ordin \
  --signer-workflow LatentOps/ordin/.github/workflows/release.yml \
  --source-digest TRUSTED_FULL_COMMIT_SHA
sha256sum --check SHA256SUMS
# macOS: shasum -a 256 --check SHA256SUMS
```

For verification with the downloaded bundle, add
`--bundle provenance.sigstore.json` to the GitHub CLI command. See
[GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify)
for trust-root and offline options. Inspect `release.json` to confirm the
intended tag/version before installing the wheel.

The publish job downloads tested artifacts by their workflow artifact ID,
rechecks checksums, source/tag/version equality, and the remote tag's current
commit, then verifies attestation identity. It does not rebuild. Existing
releases, including `v0.2.0`, are not modified retroactively to add new metadata.

## Installing releases

Users can install a stable release directly from its Git tag:

```bash
python -m pip install "git+https://github.com/LatentOps/ordin.git@v0.3.0"
```

They can also install the wheel attached to the GitHub Release.

For a v0.4 candidate, or its final release after publication, use the
[artifact quickstart](quickstart-0.4.md) to install matching core/Swarm wheels
from the verified complete bundle. The v0.3 command above remains the published
historical reference and does not imply that a v0.4 tag already exists.

For the current development tree:

```bash
python -m pip install "git+https://github.com/LatentOps/ordin.git"
```

## After publishing

Treat the released tag and artifacts as immutable. Do not replace assets with different package contents under the same version. Advance `main` to the next development version in a new PR before resuming feature work.

## Failure policy

Do not publish artifacts from a failed build by hand. Fix the source or release configuration, rerun the merge gate, and use a new version if an artifact with the previous version was already published.
