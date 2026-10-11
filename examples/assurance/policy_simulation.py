"""Checkout entrypoint for the packaged policy_simulation example."""

from ordin.assurance.examples.policy_simulation import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
