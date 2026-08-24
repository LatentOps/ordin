# Releasing Ordin

PyPI is the primary Python package repository for Ordin. GitHub Actions also retains the validated wheel and source distribution as workflow artifacts for each release build.

## One-time PyPI setup

Before enabling publishing:

1. Create or claim the `ordin` project on PyPI through its first trusted-publisher release setup.
2. Configure a PyPI Trusted Publisher for this GitHub repository:
   - owner: `LatentOps`
   - repository: `ordin`
   - workflow: `release.yml`
   - environment: `pypi`
3. Create a protected GitHub environment named `pypi` if release approvals are desired.
4. Set the repository Actions variable `PYPI_PUBLISH` to `true` only after the trusted-publisher relationship is configured.

No long-lived PyPI API token is required by the workflow.

## Preparing a release

Update the version in both:

- `pyproject.toml` -> `project.version`
- `ordin/__init__.py` -> `__version__`

Run the normal merge gate before tagging:

```bash
ruff check ordin tests
ruff format --check ordin tests
pytest -q
python -m ordin doctor
python -m build
python -m twine check dist/*
```

Merge the version change to `main`, then create the matching tag. For version `0.1.0`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow refuses a tag that does not exactly equal `v<project.version>` and also refuses a mismatch between `pyproject.toml` and `ordin.__version__`.

## Release workflow

Every `v*` tag:

1. validates version/tag consistency;
2. builds wheel and sdist;
3. runs Twine metadata validation;
4. installs the built wheel into a fresh virtual environment;
5. runs installed `ordin doctor` and a bare-intent smoke test;
6. uploads the distributions as a GitHub Actions artifact;
7. publishes the exact validated artifacts to PyPI only when `PYPI_PUBLISH=true`.

`workflow_dispatch` can be used to exercise the build/validation pipeline without publishing.

## Failure policy

Do not publish artifacts from a failed build by hand. Fix the source or release configuration, rerun the merge gate, and create a new release version/tag if an immutable PyPI version was already published.
