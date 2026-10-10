# Offline Assurance examples

From the checkout, run the synthetic profile/inventory example as a module:

```sh
python -m examples.assurance.profile_inventory \
  --repository-root tests/assurance/fixtures/repositories/payment \
  --repository-id fixture/payment --revision fixture-v1 \
  --virtual-root /fixture/payment --output .assurance-work/profile-example
```

Choose a fresh output directory; the example refuses overwrites and source-tree
output. It inventories inspected files, creates a non-authoritative threat
model, proposes profile content, and exercises protected selection/compilation
with a synthetic host boundary. It never imports fixture source or runs a tool,
scanner or model. Its declared host protection is a fixture, not installed OS
enforcement. Windows operators must protect private output with appropriate ACLs.

JSON/draft/profile artifacts are private local data with exact source references.
Markdown defaults to path aliases; `--include-source-paths` explicitly reveals
verified citations for local review. The output summary declares
`draft_authoritative: false`, `executes_actions: false`, and
`protection: synthetic_host_fixture_only`.

Review synthetic tool actions and exact approvals through the runtime wrapper:

```sh
python -m examples.assurance.gate_review --output .assurance-work/gate-example
```

Expected: the read escalates without a host receipt, the same read passes after
the bound receipt, and the protected workflow mutation is denied. The example
rechecks the action/configuration/context binding and writes redacted decision
reports. It executes no reviewed action and installs no real host enforcement.

An installed wheel can run these checkout examples with its own interpreter:

```sh
/path/to/wheel-venv/bin/python -I examples/assurance/profile_inventory.py \
  --repository-root tests/assurance/fixtures/repositories/payment \
  --repository-id fixture/payment --revision fixture-v1 \
  --virtual-root /fixture/payment --output .assurance-work/wheel-profile-example
```

On Windows use the venv's `Scripts/python.exe`. This is the working M2 SDK
example. Profile/gate review work; replay, challenge, delegation, scanner/model
and finding examples remain subsequent milestones; no unsupported commands are
advertised as implemented.
