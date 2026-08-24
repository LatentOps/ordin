# Semantic Command Analyzers

CommandGraph uses command-family analyzers when a command's safety depends on
its own option grammar rather than simple command-name matching.

The analyzer layer sits between shell parsing and the typed effect policy:

```text
shell segment
  -> normalized invocation
  -> command-family analyzer
  -> typed effect evidence + targets
  -> risk policy
  -> allow / warn / ask / block
```

If no dedicated analyzer exists, CommandGraph keeps using the generic typed
command/effect graph introduced in `commandgraph.effect_graph.v1`. Existing
risk rules remain active as an independent fallback and escalation layer.

## Analyzer contract

An analyzer receives a normalized invocation and returns:

- normalized command name;
- identified subcommand when applicable;
- flags;
- meaningful targets;
- typed `EffectEvidence`;
- analyzer name;
- optional notes when a detail is useful but does not itself determine risk.

The public registry entry point is:

```python
from commandgraph.analyzers import analyze_tokens
```

Analyzer output is deterministic, local, and contains no generated shell
commands.

## Initial analyzers

The initial registry covers:

- `rm`;
- `chmod`;
- `chown`;
- `git`;
- `curl`;
- `wget`;
- `docker`;
- `pip` including `python -m pip`;
- `npm`;
- `apt`;
- `apt-get`.

These analyzers deliberately focus on safety-relevant structure instead of
trying to implement complete clones of each CLI parser.

## Conservative fallback

A family analyzer is authoritative only when it emits typed effect evidence
for the invocation. If the family is recognized but an invocation is not
classified, CommandGraph remains uncertain rather than inventing a low-risk
interpretation.

Exact risk rules still take precedence where they are more specific. For
example, the `rm` analyzer emits typed delete/recursive-delete effects while
the existing root-filesystem deletion rule can still elevate `rm -rf /` to a
critical block.

## Adding analyzers

New analyzers should:

1. live under `commandgraph/analyzers/`;
2. register only the executable names they understand;
3. normalize wrappers and module execution through the shared base helpers;
4. emit effects from the checked-in effect catalog;
5. preserve concrete targets when meaningful;
6. include benign and risky tests;
7. include flag-order, bundled-option, wrapper, and target edge cases where
   relevant;
8. fall back to uncertainty when the invocation cannot be classified safely.

Avoid adding model calls, network lookups, shell execution, or hidden
side-effects to analyzers.
