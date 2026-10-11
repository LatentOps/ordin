"""Offline synthetic snapshot triage; never invokes Git or target code."""

from __future__ import annotations

import argparse
from pathlib import Path

from ordin.assurance import AuthorizedRepository, RepositoryScope
from ordin.assurance._json import canonical_json
from ordin.assurance.diff_triage import triage_source_diff


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    output = Path(args.output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before, after = output / "before", output / "after"
    before.mkdir()
    after.mkdir()
    (before / "README.md").write_text("Synthetic fixture\n", encoding="utf-8")
    (after / "README.md").write_text("Updated synthetic fixture\n", encoding="utf-8")
    (after / "app.py").write_text(
        "import subprocess\nsubprocess.run(['fixture-only'])\n", encoding="utf-8"
    )
    result = triage_source_diff(
        AuthorizedRepository(before, RepositoryScope("fixture/diff", "before"), "/fixture"),
        AuthorizedRepository(after, RepositoryScope("fixture/diff", "after"), "/fixture"),
    )
    (output / "triage.json").write_text(
        canonical_json(result.public_dict()) + "\n", encoding="utf-8"
    )
    print(canonical_json(result.public_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
