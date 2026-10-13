"""Regenerate fixed Assurance schema copies from reviewed in-memory definitions."""

import json
from pathlib import Path

from ordin.assurance._schemas import SCHEMAS

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    for name, schema in SCHEMAS.items():
        filename = name.replace("_", "-") + ".v1.schema.json"
        content = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        for directory in (ROOT / "schemas", ROOT / "ordin/resources/schemas"):
            (directory / filename).write_text(content, encoding="utf-8")
    print(f"wrote {len(SCHEMAS)} byte-identical source/package schema pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
