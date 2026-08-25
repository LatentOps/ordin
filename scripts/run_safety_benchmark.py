from __future__ import annotations

import argparse
import json
from pathlib import Path

from ordin.safety_benchmark import (
    DEFAULT_FUZZ_SEED,
    SafetyThresholds,
    adversarial_equivalence_errors,
    evaluate_safety,
    load_safety_fixtures,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = ROOT / "benchmarks" / "safety.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Ordin's deterministic safety benchmark.")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--seed", type=int, default=DEFAULT_FUZZ_SEED)
    args = parser.parse_args()

    fixtures = load_safety_fixtures(args.fixtures)
    report = evaluate_safety(fixtures)
    regression_errors = report.regression_errors(SafetyThresholds())
    fuzz_errors = adversarial_equivalence_errors(seed=args.seed)

    payload = report.as_dict()
    payload["fuzz_seed"] = args.seed
    payload["fuzz_errors"] = fuzz_errors
    payload["regression_errors"] = regression_errors
    payload["ok"] = not regression_errors and not fuzz_errors

    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")

    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
