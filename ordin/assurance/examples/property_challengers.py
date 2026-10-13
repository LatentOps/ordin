"""Offline generated request/contract/session properties; no fixture is executed."""

import json

from ordin.assurance import challenge_security_properties


def main() -> None:
    report = challenge_security_properties(seed=14, revision="fixture-v1", trials_per_property=32)
    assert report.failures == 0 and report.status == "inconclusive"
    print(
        json.dumps(
            {
                "status": report.status,
                "properties": len(report.runs),
                "generated": sum(v.generated for v in report.runs),
                "assessed": sum(v.evaluated for v in report.runs),
                "unresolved_properties": report.unresolved_properties,
                "host_boundary_exercised": report.host_boundary_exercised,
            }
        )
    )


if __name__ == "__main__":
    main()
