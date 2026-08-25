# Releasing Ordin

GitHub Releases currently publishes the validated Ordin artifacts. PyPI Trusted Publishing is prepared but should remain disabled until the `ordin` project and trust relationship are configured.

## Version lifecycle

Published package versions are immutable identifiers. Never build new source under a version that has already been released.

The expected lifecycle is:

1. normal development uses the next PEP 440 development version, such as `0.2.0.dev0`;
2. a release preparation PR changes both version declarations to the exact final version, such as `0.2.0`;
3. the full merge gate passes and the version PR is merged to `main`;
4. the matching `v0.2.0` tag is created and the release workflow validates/builds that exact commit;
5. immediately after the release, `main` advances to the next unique development version, such as `0.3.0.dev0`.

A published version must never be reused for different source contents, even if the earlier artifact was only attached to GitHub and not uploaded to PyPI.

Update the version in both:

- `pyproject.toml` -> `project.version`
- `ordin/__init__.py` -> `__version__`

Tests require the installed distribution metadata and runtime version to match.

## One-time PyPI setup

Before enabling PyPI publishing:

1. Create or claim the `ordin` project on PyPI through its first trusted-publisher release setup.
2. Configure a PyPI Trusted Publisher for this GitHub repository:
   - owner: `LatentOps`
   - repository: `ordin`
   - workflow: `release.yml`
   - environment: `pypi`
3. Create a protected GitHub environment named `pypi` if release approvals are desired.
4. Set the repository Actions variable `PYPI_PUBLISH` to `true` only after the trusted-publisher relationship is configured.

No long-lived PyPI API token is required by the workflow.

## Preparing a final release

Change the development version to the exact final version in both version declarations, then run the normal local gate:

```bash
pre-commit run --all-files
pytest -q
python -m build
python -m twine check dist/*
```

Open a focused release-version PR and merge only after the complete CI matrix passes.

Then create the matching tag. For a final version `0.2.0`:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The release workflow refuses a tag that does not exactly equal `v<project.version>` and refuses a mismatch between distribution and runtime versions.

## Release workflow

Every `v*` tag:

1. validates version/tag consistency;
2. builds wheel and sdist;
3. runs Twine metadata validation;
4. installs the built wheel into a fresh virtual environment;
5. runs installed `ordin doctor` and a bare-intent smoke test;
6. uploads the distributions as a GitHub Actions artifact;
7. publishes the exact validated artifacts to PyPI only when `PYPI_PUBLISH=true`.

`workflow_dispatch` can exercise the build/validation pipeline without publishing.

## After publishing

Treat the released tag and artifacts as immutable. Do not replace assets with different package contents under the same version. Advance `main` to the next development version in a new PR before resuming feature work.

## Failure policy

Do not publish artifacts from a failed build by hand. Fix the source or release configuration, rerun the merge gate, and use a new version if an artifact with the previous version was already published externally.
