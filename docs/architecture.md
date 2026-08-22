# CommandGraph Architecture

CommandGraph is intentionally local-first and dependency-light. The safety
layer is split into shell structure, typed command semantics, policy evidence,
and review output rather than treating a command as a single regex string.

```text
CLI / Python API
      |
      +-----------------------+
      |                       |
intent search            shell review
      |                       |
command cards             shell parser
      |                       |
synonyms / ranking       command tokens
      |                       |
      |                 typed effect graph
      |                       |
      |                 effect catalog
      |                       |
      |                 risk rules
      |                       |
      +-----------+-----------+
                  |
        human-readable / JSON
```

## Typed Command Graph

Command cards remain the source of command discovery metadata, but may now also
declare:

- command-level effects;
- subcommands and their effects;
- flags and their effects;
- affected resource types;
- required privilege/capability boundaries;
- safer command alternatives.

The graph is constructed in memory. No graph database is required.

The resulting relationship model is:

```text
intent -> command
command -> subcommand
command/subcommand -> flag
command/subcommand/flag -> effect
effect -> resource
command -> safer alternative
command -> required privilege
```

See [effect-graph.md](effect-graph.md) for the data format and policy behavior.

## Safety Evidence

Review combines independent evidence sources:

1. shell structure and nested execution boundaries;
2. explicit high-risk rules;
3. typed semantic effects from command cards;
4. coarse `default_risk` only when typed effects are unavailable.

This ordering lets migrated commands become more precise without breaking old
cards. A read-only Git subcommand can evaluate lower than the coarse Git
default, while destructive flags such as `git reset --hard` can evaluate
higher.

Unknown commands remain uncertain rather than being silently treated as safe.

## Why Not Start With RL?

Level 1 is search and ranking. Retrieval, synonyms, and supervised ranking are
better first tools than RL.

RL may fit later when the system has:

- safe sandboxes;
- multi-step task traces;
- human accept/reject feedback;
- clear success metrics;
- constrained action templates.

Even then, use constrained RL over a safe command graph, not free-form shell
generation.

## Project Scope

CommandGraph can discover and review terminal commands locally.

CommandGraph does not provide:

- account management;
- team analytics;
- centralized command governance;
- remote command execution services;
- required hosted models or cloud safety services.

The core system should remain a local Linux command discovery and safety
review primitive that shells, agents, IDEs, and broader governance systems can
call.
