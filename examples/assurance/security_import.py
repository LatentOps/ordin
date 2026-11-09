"""Checkout entrypoint for the packaged security_import example."""

from ordin.assurance.examples.security_import import fixture, main

__all__ = ["fixture", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
