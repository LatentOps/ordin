"""Run the complete owned offline example suite from an installed wheel."""

import argparse
import json
from pathlib import Path

from . import run_examples


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scratch-root", type=Path, help="Existing private writable temporary root"
    )
    args = parser.parse_args(argv)
    print(json.dumps(run_examples(scratch_root=args.scratch_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
