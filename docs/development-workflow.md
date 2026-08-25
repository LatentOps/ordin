# Development workflow

Ordin uses `main` plus short-lived issue/feature branches. A permanent `dev` integration branch is intentionally not required for the current repository size: pull requests target `main`, CI validates the merge result, and protected-branch/review rules can be applied directly to `main`.

## Local development tools

Install the development extra and Git hooks:

```bash
python -m pip install -e ".[dev]"
pre-commit install
```

Run the shared quality and repository-integrity gate:

```bash
pre-commit run --all-files
```

Then run the complete behavioral suite:

```bash
pytest -q
```

The pre-commit configuration is the source of truth for Ruff lint and formatting checks, staged mypy boundary checks, Python compilation, `ordin doctor`, and the Ordin namespace guard. CI executes the same configuration instead of maintaining a second command list.

Mypy adoption remains staged around typed public/runtime boundaries. New public modules should be added to the pre-commit mypy hook as they are introduced rather than weakening checking globally.

## CI merge gate

Every pull request to `main` runs:

- `pre-commit validate-config`;
- `pre-commit run --all-files`;
- the full test suite on Python 3.10, 3.11, 3.12, and 3.13;
- `ordin doctor` on every supported Python version;
- wheel and source-distribution builds;
- Twine metadata validation;
- installation of the built wheel into a clean virtual environment;
- installed CLI and public-API smoke tests;
- isolated package and CLI checks on Debian and Fedora;
- distribution artifact upload for inspection.

Changes should only merge after every required job is green on the exact PR head.

## Packaging checks

When working specifically on release metadata or packaging, the CI package job is authoritative. For an additional local check:

```bash
python -m build
python -m twine check dist/*
```

Do not hand-publish artifacts produced from a failing source tree.
