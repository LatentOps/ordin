"""A static local diagnostic console. It contains no privileged control stream."""

import base64
from html import escape
import json

from ordin.schema import validate_named_schema


def render_swarm_dashboard(snapshot: dict) -> str:
    if validate_named_schema("swarm_operator_snapshot", snapshot):
        raise ValueError("bounded operator snapshot required")

    def value(item):
        return escape(str(item), quote=True)

    def table(columns, rows):
        header = "".join("<th>" + value(name) + "</th>" for name in columns)
        body = "".join(
            "<tr>"
            + "".join("<td>" + value(row.get(name, "unknown")) + "</td>" for name in columns)
            + "</tr>"
            for row in rows
        )
        return "<table><thead><tr>" + header + "</tr></thead><tbody>" + body + "</tbody></table>"

    nodes = snapshot["graph"]["nodes"][:32]
    positions = {
        row["event_ref"]: (70 + (i % 4) * 220, 40 + (i // 4) * 70) for i, row in enumerate(nodes)
    }
    svg = []
    for edge in snapshot["graph"]["edges"]:
        if edge["from_ref"] in positions and edge["to_ref"] in positions:
            x1, y1 = positions[edge["from_ref"]]
            x2, y2 = positions[edge["to_ref"]]
            svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#718096"/>')
    for row in nodes:
        x, y = positions[row["event_ref"]]
        svg.append(
            f'<circle cx="{x}" cy="{y}" r="10" fill="#2563eb"/><text x="{x + 15}" y="{y + 5}">{value(row["kind"])}</text>'
        )
    graph = (
        '<svg role="img" aria-label="Reported causal edges; successful exploitation remains unknown" viewBox="0 0 900 '
        + str(max(100, ((len(nodes) + 3) // 4) * 70))
        + '">'
        + "".join(svg)
        + "</svg>"
    )
    raw = json.dumps(snapshot, sort_keys=True, allow_nan=False).encode()
    download = base64.b64encode(raw).decode("ascii")
    metrics = "".join(
        '<div class="metric"><strong>'
        + value(snapshot["metrics"][name])
        + "</strong><span>"
        + value(name.replace("_", " "))
        + "</span></div>"
        for name in (
            "intent_reviews",
            "observed_completions",
            "reported_completions",
            "unknown_outcomes",
            "advisory_risk_signals",
        )
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'"><title>Ordin local swarm diagnostics</title><style>body{font:15px system-ui;margin:32px;background:#f4f7fa;color:#172033}main{max-width:1200px;margin:auto}section{background:white;padding:20px;margin:20px 0;border:1px solid #dde4ee;border-radius:10px}table{width:100%;border-collapse:collapse;display:block;overflow:auto}th,td{padding:9px;text-align:left;border-bottom:1px solid #ddd;max-width:360px;overflow-wrap:anywhere}h1{font-size:28px}.metrics{display:flex;gap:20px;flex-wrap:wrap}.metric{display:grid;gap:8px}.metric strong{font-size:26px}svg{width:100%}svg text{font:12px system-ui}a{color:#1d4ed8}</style><main><h1>Swarm diagnostics</h1><p>Local diagnostic view. Intent, host reports, observed outcomes and advisory model risk remain separate. Unmediated paths and earlier history remain unknown. This dashboard grants no permissions.</p><p>Live authenticated source: '
        + value(snapshot["verified_live_source"])
        + '</p><section class="metrics">'
        + metrics
        + "</section><section><h2>Agents</h2>"
        + table(
            ("actor_ref", "phase", "containment", "generation", "reported_mode"), snapshot["agents"]
        )
        + "</section><section><h2>Coverage and gaps</h2>"
        + table(
            ("actor_ref", "capability", "reported_state", "verified_state", "proof_gaps"),
            snapshot["coverage"],
        )
        + "<p>"
        + value(", ".join(snapshot["proof_gaps"]))
        + "</p></section><section><h2>Causal graph</h2><p>Edges show reported causality; they do not prove exploitation.</p>"
        + graph
        + "</section><section><h2>Budgets</h2>"
        + table(
            ("metric", "maximum", "held", "consumed", "remaining", "claim"), snapshot["budgets"]
        )
        + "</section><section><h2>Incidents</h2>"
        + table(
            (
                "incident_ref",
                "operation",
                "affected_count",
                "outcomes",
                "notifications_complete",
                "resumed",
            ),
            snapshot["incidents"],
        )
        + "</section><section><h2>Timeline</h2>"
        + table(("sequence", "kind", "state", "evidence", "admitted_at"), snapshot["timeline"])
        + '</section><p><a download="ordin-incident-bundle.json" href="data:application/json;base64,'
        + download
        + '">Export this redacted incident snapshot</a></p></main></html>'
    )
