"""Checkout entrypoint for the packaged gate_review example."""

from ordin.assurance.examples.gate_review import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
