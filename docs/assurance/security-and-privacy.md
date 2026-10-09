# Assurance security and privacy

Default imports, ordinary `Ordin`/`AgentGate`, profile validation and local
inventory do not contact a scanner or hosted model. Repository files, comments,
instruction documents, imported artifacts and model output remain untrusted.
Only separately protected host APIs select profiles or issue trusted evidence.
Ordinary JSON decoding cannot activate authority.

Repository/file readers anchor to an explicit authorized directory, reject
traversal, symlinks/reparse points, hardlinks, remote/device namespaces and
nonregular files, and bound bytes/nesting/counts. POSIX directory descriptors
use `O_NOFOLLOW`. Windows retains directory handles without delete sharing,
opens reparse points themselves and validates the actual file handle/link count;
it also avoids recalling offline storage. Sharing flags remain effective while
handles are open, and delete access covers renaming. These are the platform
semantics documented by [Microsoft's CreateFileW reference](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [Python's descriptor APIs](https://docs.python.org/3/library/os.html#os.open).
Failed opens release handles; snapshot verification catches changed source.

Private profile/analysis artifacts can contain exact asset/source references.
Treat `as_dict()` as local private serialization. Public Markdown rendering
redacts paths/assets by default and requires an explicit flag to reveal them.
Raw source, secret values, tool-output bodies and repository instructions are
not retained by the inventory. Hashes preserve correlation, not confidentiality;
low-entropy names and values can be guessed.

Store private evidence and approved configuration outside agent write scope,
with restrictive permissions/ACLs. Use separate directories for raw evidence,
synthetic examples and public reports. Operators own retention, rotation and
manual deletion; stop pending work before changing configuration, revoking host
authority or deleting evidence. No automatic upload, publication, disclosure,
remediation installation, network listener or dashboard is provided.

Protected configuration and capability boundaries are external host obligations.
Declared runtime guarantees must correspond to actually enforced rights and
correct physical/runtime path mappings. Unknown protection refuses activation.
An API verification result is not proof the host installed enforcement. A local
administrator or malicious code inside the trusted host process remains outside
these ordinary file/API protections. Final execution must recheck exact action,
profile, grant, session/epoch and active policy bindings at use time.

The current source inventory is deliberately incomplete analysis. Imported or
static claims do not become observed exploitation, and uninspected deployment
context does not become safety. Real scanner/model setup, third-party licensing,
hosted consent and patch workflows remain separate optional milestones.
