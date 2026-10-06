from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "integrations/openshell")]
from ordin.runtime_codec import read_runtime_json
from ordin_openshell.corpus import evaluate_runtime_corpus


def main():
    parser = argparse.ArgumentParser(
        description="Run the bounded runtime capability/evidence adversarial corpus"
    )
    parser.add_argument("--input", default=str(ROOT / "benchmarks/runtime_enforcement.json"))
    parser.add_argument("--json-out")
    args = parser.parse_args()
    result = evaluate_runtime_corpus(read_runtime_json(args.input))
    text = json.dumps(result, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
