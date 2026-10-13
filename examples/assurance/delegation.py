"""Checkout entrypoint for the packaged delegation example."""

from ordin.assurance.examples.delegation import fixture, main

__all__ = ["fixture", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
