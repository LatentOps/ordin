"""Checkout entrypoint for the packaged property_challengers example."""

from ordin.assurance.examples.property_challengers import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
