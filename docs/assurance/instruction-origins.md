# Host instruction and data origins

`register_instruction_origin` records a host declaration about actual bytes it
received. It retains a bounded content digest, byte-span digest, classification,
source kind and exact principal/repository/session/epoch scope. Source kinds keep
authorized user instructions, repository files, MCP results, web content, model
reasoning and unknown origins distinct. None grants execution or policy rights.
Content words such as `role=system`, `trusted=true` and `approved_policy` do not
change the source kind or classification.

`correlate_source_use` requires that the selected proposed-action parameter is
exactly the same UTF-8 bytes as the registered source span. It records hashes and
a bounded field path, then binds the receipt to the exact action digest. It does
not infer persuasion, successful execution, or a data transfer. A downstream
attack-path builder must still distinguish copied bytes from causal influence
and use authenticated runtime observations for completed effects.

Both handles are deeply immutable and require a private host issuance seal.
Ordinary JSON, changed fields, other principals, stale epochs, changed policy
selections and mismatched action bytes cannot supply a valid handle. The host
API is called only after the application has identified the real input origin;
these Python boundaries do not defend against malicious code in the trusted
host process. A JSON export is an audit record, not a way to restore authority.

The functions do not read source files or retain raw bytes. Byte spans are
bounded to one MiB; source-use paths have at most eight fields and select UTF-8
text only. Unicode is not normalized. If a repository `SourceReference` is
provided, its version and complete content digest must match the declared
bytes. The host owns verification that those bytes actually came from that file.
Origin exports can contain an explicitly provided relative source reference and
public field labels; applications must choose labels suitable for disclosure.
The future default graph renderer will omit source paths and full tool output.

```python
from ordin import ActionEnvelope
from ordin.assurance import correlate_source_use, register_instruction_origin, verify_source_use

# `host_source` is selected by the protected host integration, not agent JSON.
origin = register_instruction_origin(
    host_source, origin_id="fixture-input", kind="mcp_result",
    classification="public", content="synthetic fixture data",
)
action = ActionEnvelope("tool", "call", {"body": "synthetic fixture data"})
use = correlate_source_use(
    host_source, origin, action, use_id="fixture-use",
    argument_path=("parameters", "body"),
)
assert verify_source_use(host_source, origin, use, action)
```

M6 remains in progress. Attack-path construction, source-flow invariant
assessment, causal proof limits, counterevidence collection and cross-agent
delegation integration are not implemented by these handles alone.
