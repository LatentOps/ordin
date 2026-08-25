# Ordin architecture

Ordin is a local command-intelligence and pre-execution safety engine. Discovery and safety share the same curated command semantics, but they remain separate stages so ranking cannot silently become policy and policy cannot fabricate commands.

## End-to-end pipeline

```text
                          +----------------------+
natural-language intent ->| deterministic search |-> command candidates
                          +----------+-----------+
                                     |
command text ------------------------+
                                     v
                           shell parsing
                                     |
                                     v
                    executable / action normalization
                                     |
                  +------------------+------------------+
                  |                                     |
                  v                                     v
          semantic analyzers                    typed effect graph
                  |                                     |
                  +------------------+------------------+
                                     |
                                     v
                         structured safety evidence
                                     |
                     +---------------+---------------+
                     |               |               |
                  context        risk rules        trace
                     |               |               |
                     +---------------+---------------+
                                     |
                                     v
                              policy merge
                                     |
                                     v
                         allow / warn / ask / block
```

The system is deterministic by default and requires no hosted service.

## 1. Command intelligence

Search maps user intent to known command metadata. The default ranker combines:

- BM25-style lexical retrieval;
- intent, alias, and command-name signals;
- template/slot metadata;
- local executable availability;
- Linux distribution compatibility.

An optional local semantic reranker can reorder only a bounded deterministic candidate set. It cannot bypass the deterministic retrieval path or safety review.

## 2. Shell structure

Safety review starts from shell structure rather than treating the full string as one regex target. The parser identifies compound segments, pipelines, substitutions, grouped commands, common wrappers, redirections, and nested shell payloads such as `bash -c`.

Each executable action is reviewed independently and the overall result conservatively preserves the strongest finding.

## 3. Semantic analyzers

High-value command families have dedicated analyzers for argument-sensitive behavior. They convert concrete invocation details into structured effects and resources, for example:

```text
rm -rf ./build
  -> filesystem.delete
  -> filesystem.recursive_delete
  -> path:./build

git push --force-with-lease
  -> git.remote_write
  -> git.history_rewrite

curl --data-binary @payload.json https://example.com
  -> network.upload
```

The generic typed resolver remains a fallback for commands without a dedicated analyzer.

## 4. Typed effect graph

Curated command cards can express:

```text
intent -> command
command -> subcommand
command/subcommand -> flag
command/subcommand/flag -> effect
effect -> resource
command -> safer alternative
command -> required privilege
```

Effects are shared semantic vocabulary, not policy decisions. The effect catalog attaches reusable risk metadata and safer next steps to those semantics.

The graph is built in memory. Ordin does not require a graph database.

## 5. Context-aware review

A review request may include explicit local execution context:

- working directory;
- shell;
- effective user ID;
- interactive/non-interactive mode;
- repository root;
- agent/runtime identity.

Context is caller-supplied or locally derived by integrations. Core review does not collect remote environment data.

## 6. Trace-aware review

For agent runtimes, a bounded action trace can capture recent commands. Ordin re-evaluates prior command text through the same local semantic machinery rather than trusting caller-provided risk labels.

Trajectory rules currently cover patterns such as:

- secret read -> network upload;
- download -> permission change -> execute;
- repeated destructive actions;
- repeated privilege escalation.

Trace evidence is monotonic: it can elevate the current decision but cannot weaken a stronger single-command finding.

## 7. Policy merge

Evidence sources are intentionally compositional:

1. shell structure;
2. semantic analyzers;
3. typed effects;
4. exact risk rules;
5. execution context;
6. recent action trajectory;
7. coarse command defaults only where richer semantics are unavailable.

The output is one of `allow`, `warn`, `ask`, or `block`. Unknown or insufficiently classified commands use `ask` rather than silently becoming low risk.

## 8. Interfaces

The same engine is exposed through:

- `ordin` CLI;
- Python modules;
- versioned JSON review requests/results;
- opt-in Bash/Zsh integration;
- command/effect graph export;
- modular command packs.

Public machine payloads use the `ordin.*.v1` schema namespace.

## Project boundaries

Ordin deliberately does not provide:

- remote command execution;
- automatic shell-history upload;
- required cloud inference;
- free-form shell-program generation;
- centralized enterprise account/governance services.

Those systems can call Ordin as a local action-intelligence and safety primitive instead of being embedded into the core package.
