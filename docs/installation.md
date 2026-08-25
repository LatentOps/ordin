# Installation

Ordin is distributed as the Python package `ordin` and installs one canonical console command: `ordin`.

## Current public release

Ordin v0.1.0 is published as a GitHub release. PyPI publishing is not enabled yet.

Install the validated v0.1.0 wheel directly:

```bash
python -m pip install https://github.com/LatentOps/ordin/releases/download/v0.1.0/ordin-0.1.0-py3-none-any.whl
```

Then verify the installation:

```bash
ordin --help
ordin doctor
ordin make file runnable
```

The release also includes a source distribution for environments that prefer to build locally.

## Optional semantic reranking

The deterministic search and safety paths have no ML runtime dependency. Until the optional extra is published through PyPI, install semantic support from a checkout:

```bash
git clone https://github.com/LatentOps/ordin.git
cd ordin
python -m pip install ".[semantic]"
```

A semantic model must be supplied from an explicit local path. Ordin does not automatically download one.

## Install from source

For the current development tree:

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
