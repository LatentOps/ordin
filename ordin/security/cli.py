"""Ordin Security command surface; execution stays explicit and bounded."""

from __future__ import annotations

from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    from ordin.assurance.cli import main as assurance_main

    return assurance_main(argv, prog="ordin security", security_cli=True)


if __name__ == "__main__":
    raise SystemExit(main())
