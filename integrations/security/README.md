# Ordin Security artifact adapter

The adapter namespace reexports Ordin's built-in zero-dependency offline
importer. It starts no scanner/provider and requires no account or API key.
Install this separate adapter only when an application uses the
`ordin_security` namespace. Ordinary `ordin` also ships the data-only API
under `ordin.security` and the `ordin security import` command.

```python
from pathlib import Path
from ordin.assurance import RepositoryScope
from ordin_security import ImportScope, import_native_json

scope = ImportScope(
    Path("/private/scanner-output"), RepositoryScope("example/repo", "reviewed-sha")
)
report = import_native_json(scope)
print(report.public_dict())
```

Upstream schema copies are pinned to OpenAI Codex Security commit
`6f4c62875baa310c6f18608035309e77bc8e808b` (TypeScript SDK `0.2.0`), with original
Git blob hashes in `resources/upstream.json`. The vendored schemas remain under
Apache-2.0; see `resources/LICENSE.upstream`. No upstream executable code is
loaded. Repository filenames, Markdown, code evidence, validation and remediation
are untrusted claim data. Source references and sealed content hashes can be
verified, but never confer execution permission or finding confirmation.

See [the main integration documentation](../../docs/assurance/security-integration.md)
for the import contract, host-only scanner API, configuration/isolation review,
offline diff triage and privacy limits. `ordin_security.provider` reexports
the optional wrapper; importing it never starts a process. The optional
`examples/private-diff-scan.yml` is outside active workflows and requires a
separately reviewed private runner, protected environment and installation.
