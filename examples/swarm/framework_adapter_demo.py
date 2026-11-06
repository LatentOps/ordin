"""Run real pinned local SDK fixtures; this does not download or call a model."""

import argparse
import json

from ordin_swarm.demo import run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--framework", choices=("custom", "langgraph", "crewai", "autogen"), default="custom"
    )
    args = parser.parse_args()
    report = run(args.framework)
    print(json.dumps(report, sort_keys=True, indent=2))
    return (
        0
        if report["allowed_read_completed"]
        and report["private_handoff_delivered"]
        and report["source_flow_violated"]
        and not report["egress_callbacks"]
        and not report["child_callbacks"]
        and report["denied_reviews"] >= 2
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
