# Installation

Ordin is packaged as the Python distribution `ordin` and installs two equivalent console commands: `ordin` and the shorter `ordin`.

## PyPI

After a release is published to PyPI, the recommended CLI installation is:

```bash
pipx install ordin
```

or with `uv`:

```bash
uv tool install ordin
```

A normal Python environment can use:

```bash
python -m pip install ordin
```

Then verify the installation:

```bash
ordin doctor
ordin make file runnable
```

## Optional semantic reranking

The deterministic BM25 search path has no ML runtime dependency. Local semantic reranking is optional:

```bash
python -m pip install "ordin[semantic]"
```

Ordin still requires an explicit local model path and does not automatically download a model.

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
```

## Supported Python

Ordin supports Python 3.10 through 3.13. The CI matrix tests each supported version before merge.
