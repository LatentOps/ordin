# Five-minute offline quickstart

Install a built local Ordin wheel into a new environment. These commands need no
account, scanner, model weights or network package lookup:

```bash
python -m venv .assurance-demo
python -m pip --python .assurance-demo install --no-index --no-deps /path/to/ordin-0.4.0.dev0-py3-none-any.whl
```

Activate that environment using your shell's normal command, then run:

```bash
python -I -m ordin.assurance.quickstart
```

The example creates and removes owned temporary synthetic fixtures. It executes
no proposed command, scanner, model, host tool or live exploit, installs no policy
and publishes no result. The JSON demonstrates:

- Validated profile content with `approved=false`.
- A separately protected synthetic profile selection: safe read executes in
  review, network action is denied in review.
- Dry-run policy comparison with a newly escalated write and zero critical misses.
- An intentionally injected checker defect with minimized counterexamples replayed.
- A bounded evidence graph with no runtime execution observations.
- Child authority containment over declared maxima, without issuing a grant.
- Offline vulnerability and fix-verdict import with confirmation not performed.

These are fixtures and finite checks, not real repository effectiveness evidence.
The exact output contract and test/setup limits are documented in
[the Assurance reference](../../docs/assurance/cli-and-api.md).

For individual commands, use the installed `ordin-assure` entrypoint, or the
equivalent `python -I -m ordin.assurance.cli`. JSON is the default; `--json` is
accepted explicitly. Each command has `--help`. Input `-` reads bounded JSON stdin.

```bash
ordin-assure challenge list --json
ordin-assure profile validate /private/profile-content.json --json
ordin-assure profile inspect /private/profile-content.json --json
ordin-assure invariants check --profile /private/profile-content.json --action /private/action.json --json
```

The invariant command is an unapproved-content preview. A declared forbidden
effect can be reported as a match, while approval, grant, credential, provenance
and other host-dependent checks stay inconclusive. The command applies no profile
and returns no execution authority. Exit 1 identifies a restriction/violation;
exit 2 identifies unknown/unsupported input or proof. Baseline hard denials persist.

Optional extended workflows remain explicit:

```bash
python -I -m ordin.assurance.validation_demo
python -I -m ordin_decision_models.demo
```

The first is an owned synthetic finding/policy-fix example. The second requires
installing the separate decision-model wheel and uses predetermined offline mock
values for disabled/shadow/escalation modes. It neither loads Laya nor contacts
TypeSafe. Real local setup and hosted disclosure require actual protected host
selection, approval/isolation receipts, bounded resources and opt-in. See
[decision models](../../docs/assurance/decision-models.md).

The standalone [delegation example](delegation.py) also uses wholly synthetic
state. Existing Claude/Codex/Cursor/MCP adapters can be composed through
`AssuranceAdapterGate`; the host retains execution, approval UI, state and broker
ownership. See [adapter composition](../../docs/assurance/adapter-composition.md).

The earlier checkout examples remain available for explicit private artifacts:

```bash
python -m examples.assurance.profile_inventory \
  --repository-root tests/assurance/fixtures/repositories/payment \
  --repository-id fixture/payment --revision fixture-v1 \
  --virtual-root /fixture/payment --output .assurance-work/profile-example
python -m examples.assurance.gate_review --output .assurance-work/gate-example
```

Use a fresh output directory. These examples refuse overwrite/source-tree output,
retain source references privately and use synthetic protected host declarations.
The gate example demonstrates receipt-free escalation, bound approval and
protected-workflow denial. It executes no action or real host enforcement.
`--include-source-paths` explicitly exposes verified citations in local inventory
review; Windows private output requires operator-managed ACLs.
