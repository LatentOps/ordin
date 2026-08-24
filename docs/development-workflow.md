# Development workflow

CommandGraph uses `main` plus short-lived issue/feature branches. A permanent `dev` integration branch is intentionally not required for the current repository size: pull requests target `main`, CI validates the merge result, and protected-branch/review rules can be applied directly to `main`.

## Local development tools

Install the development extra:

```bash
python -m pip install -e ".[dev]"
```

The standard quality commands are:

```bash
ruff check commandgraph tests
ruff format --check commandgraph tests
mypy commandgraph/entrypoint.py commandgraph/context.py commandgraph/trace.py commandgraph/enforcement.py commandgraph/availability.py
pytest -q
python -m commandgraph doctor
python -m build
python -m twine check dist/*
```

Ruff is the formatter and linter. Mypy adoption is staged around the typed public/runtime boundary first; the checked module set should expand as older modules are tightened rather than weakening the type checker globally.

## CI merge gate

Every pull request to `main` runs:

- Ruff linting and formatting checks
- staged mypy static checks
- Python compilation
- the full test suite on Python 3.10, 3.11, 3.12, and 3.13
- `commandgraph doctor` on every supported Python version
- wheel and source-distribution builds
- Twine metadata validation
- installation of the built wheel into a clean virtual environment
- installed CLI, doctor, and bare-intent smoke tests
- distribution artifact upload for inspection

Changes should only merge after all required jobs are green.
