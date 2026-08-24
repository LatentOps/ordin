# Enforcement and stdin review

Ordin reports review decisions by default without changing its historic
process exit behavior. Enforcement is opt-in so existing scripts are not broken.

## Exit codes

When enforcement is active, Ordin uses stable decision exit codes:

| Decision | Exit code |
| --- | ---: |
| `allow` | 0 |
| `warn` | 10 |
| `ask` | 20 |
| `block` | 30 |

Input/schema/context errors use exit code `2`.

`--enforce` uses `warn` as its threshold, so every non-allow decision returns
its non-zero decision code. `--fail-on` implies enforcement and can relax the
threshold:

```bash
ordin check "chmod 600 file.txt" --enforce
ordin check "chmod 600 file.txt" --fail-on block
```

The second form exits 0 for warn/ask and 30 only for block. `--fail-on ask`
allows warnings but fails on ask or block.

## Versioned stdin requests

`review --stdin` reads exactly one `ordin.review_request.v1` JSON object
from standard input. It validates the request against the checked-in schema
before review.

```bash
cat <<'JSON' | ordin review --stdin --json --enforce
{
  "schema_version": "ordin.review_request.v1",
  "command": "rm -rf .",
  "intent": "clean generated files",
  "context": {
    "cwd": "/repo/build",
    "shell": "bash",
    "euid": 1000,
    "interactive": false,
    "repo_root": "/repo",
    "agent": "coding-agent"
  }
}
JSON
```

For stdin mode the versioned request is authoritative. `--stdin` cannot be
combined with `--intent` or context flags. Output mode and enforcement options
remain CLI-level controls.

## Agent integration

A runtime can treat exit 0 as executable and any other enforcement code as a
reason not to execute automatically:

```text
agent proposes command
       |
       v
ordin review --stdin --json --enforce
       |
       +-- 0  -> execute
       +-- 10 -> warning policy / approval
       +-- 20 -> ask for missing context or human decision
       +-- 30 -> block
```

JSON mode writes one JSON result (or one structured input error) to stdout so
callers can parse stdout without filtering human diagnostics.
