# Ordin Assurance baseline inventory

The immutable comparison point is `9f2568f70c677f607d631e252f609207f6a2cd60`,
Ordin `0.4.0.dev0`, captured on Windows 11 with Python 3.13.12.
[The machine inventory](evidence/baseline-inventory.json) records every exported
name, all public top-level classes/functions in tracked Python source, all 40
schema registrations, file hashes, and the complete 224-entry baseline wheel
inventory. It also records hashes of the existing historical evaluation reports.
Do not regenerate that artifact from the candidate implementation.

| Representative action | Review | AgentGate disposition |
| --- | --- | --- |
| `git status --short` | allow | execute |
| Unknown MCP tool | ask | escalate |
| `rm -rf /` | block | deny |
| Generic file write | ask | escalate |
| Generic network upload | ask | escalate |

These synthetic fixtures preserve exact envelopes and reviews in the inventory.
They establish compatibility examples, not broad safety effectiveness.

The existing entrypoints are `ordin`, `ordin-claude-hook`, `ordin-codex-hook`,
`ordin-cursor-hook`, `ordin-mcp-proxy`, and `ordin-mcp-http`. The explicit package
list includes `ordin` and `ordin.analyzers`. Core dependencies are empty. Optional
command-search semantics belong to the separate `semantic` extra.

Existing CI includes Quality, Safety benchmark, Python 3.10–3.13, macOS 15
Python 3.13, installed-wheel checks, CodeQL Python, Dependency review, Workflow
security, and runtime-extension build/release checks. Source workflow hashes
are frozen in the machine inventory. Assurance must add gates without changing
their existing thresholds or privileges.

Preserve the distinct `REVIEW_PRECEDENCE` and `ENFORCEMENT_ORDER` in
`ordin/policy.py`. Final disposition fusion may use execute < escalate < deny;
it must not reuse that ordering for review labels. Preserve the host-only
`RuntimeEvidenceSource` constructor/restore boundary and all exact request v2
commitments, session epochs, action digests and runtime contract IDs.

The baseline doctor passes: 48 commands, 16 risk rules, 43 effects, 40 schemas,
11 loaded packs, and zero schema/resource/graph errors. The complete nine-case
Agent Safety Corpus passes. Current full-suite and benchmark results are tracked
in [the implementation report](implementation-report.md). Historical reports
are reference evidence only; candidate results require their own revision.
