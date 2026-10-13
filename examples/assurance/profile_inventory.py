"""Checkout entrypoint for the packaged profile_inventory example."""

from ordin.assurance.examples.profile_inventory import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
