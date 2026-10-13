"""Checkout entrypoint for the packaged source_diff example."""

from ordin.assurance.examples.source_diff import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
