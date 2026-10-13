"""Checkout entrypoint for the packaged codex_import example."""

from ordin.assurance.examples.codex_import import fixture, main

__all__ = ["fixture", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
