# Installation

Ordin is distributed as the Python package `ordin` and installs one canonical console command: `ordin`.

## Recommended CLI installation

Use an isolated tool environment:

```bash
pipx install ordin
```

or:

```bash
uv tool install ordin
```

Then verify the installation:

```bash
ordin --help
ordin doctor
ordin make file runnable
```

A normal Python environment can use:

```bash
python -m pip install ordin
```

## Optional semantic reranking

The deterministic search and safety paths have no ML runtime dependency. Local semantic reranking is optional:

```bash
python -m pip install "ordin[semantic]"
```

A semantic model must be supplied from an explicit local path. Ordin does not automatically download one.

## Install from source

For an unreleased checkout:

```bash
git clone https://github.com/LatentOps/ordin.git
cd ordin
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
pre-commit install
```

Run the shared local/CI quality gate with:

```bash
pre-commit run --all-files
```

Run the full behavioral test suite separately:

```bash
pytest -q
```

The pre-commit gate covers Ruff lint and formatting, staged mypy checks, Python compilation, `ordin doctor`, and repository namespace integrity. CI executes the same pre-commit configuration before its Python-version, package, and Linux compatibility jobs.

## Supported Python and Linux validation

Ordin supports Python 3.10 through 3.13. CI tests every supported Python version and also performs isolated installed-CLI smoke tests on Debian and Fedora in addition to the standard Ubuntu runner.
