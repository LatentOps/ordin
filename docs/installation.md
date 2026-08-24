# Installation

CommandGraph is packaged as the Python distribution `commandgraph` and installs two equivalent console commands: `commandgraph` and the shorter `cmdgraph`.

## PyPI

After a release is published to PyPI, the recommended CLI installation is:

```bash
pipx install commandgraph
```

or with `uv`:

```bash
uv tool install commandgraph
```

A normal Python environment can use:

```bash
python -m pip install commandgraph
```

Then verify the installation:

```bash
cmdgraph doctor
cmdgraph make file runnable
```

## Optional semantic reranking

The deterministic BM25 search path has no ML runtime dependency. Local semantic reranking is optional:

```bash
python -m pip install "commandgraph[semantic]"
```

CommandGraph still requires an explicit local model path and does not automatically download a model.

## Install from source

For an unreleased checkout:

```bash
git clone https://github.com/LatentOps/command-graph.git
cd command-graph
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Supported Python

CommandGraph supports Python 3.10 through 3.13. The CI matrix tests each supported version before merge.
