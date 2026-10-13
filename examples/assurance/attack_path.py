"""Checkout entrypoint for the packaged attack_path example."""

from ordin.assurance.examples.attack_path import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
