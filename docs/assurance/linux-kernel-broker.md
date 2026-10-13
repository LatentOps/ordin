# Optional Linux kernel broker

The explicit Linux broker runs only the existing closed synthetic predicate
language. It reads bounded source/test data from three pipes, vets it, applies
kernel restrictions to its own disposable process, verifies those restrictions,
then evaluates the predicate. It never imports or launches target repository
scripts, real scanners, model weights or proposed actions. Ordinary imports,
constructors, reviews and CLI commands do not initialize this broker.

The supported profile is Linux x86-64, little-endian, with `/proc` and enabled
Landlock ABI 1 or later plus seccomp filter support. Other platforms/ABIs or
missing primitives return unavailable/inconclusive; there is no weaker execution
fallback. It uses Python's standard library, without Docker, additional packages,
host mounts, privileged configuration changes or a network listener.

The broker applies a deny-all Landlock filesystem ruleset and a fixed
architecture-checked seccomp syscall allowlist. The filter independently denies
filesystem opens and mutation, sockets, fork/clone, executable launch, credential
changes, ptrace, mounts and resource-limit widening. Only memory management,
pipe I/O, minimal process readback and exit operations remain. Inputs are
controlled in-memory fixtures; no filesystem access is needed after entry.
Only stdin/stdout/stderr pipes survive, environment variables are cleared,
`no_new_privs` is set and core dumps are disabled. CPU and address-space hard
limits match the selected runtime. Descriptor and process ceilings are three
and one; syscall filtering additionally denies process creation even for uid 0.

The implementation follows the kernel's
[Landlock ABI guidance](https://docs.kernel.org/userspace-api/landlock.html) and
[seccomp filtering contract](https://docs.kernel.org/userspace-api/seccomp_filter.html).
The syscall map is pinned to the
[Linux 5.15 x86-64 table](https://github.com/torvalds/linux/blob/v5.15/arch/x86/entry/syscalls/syscall_64.tbl).
Landlock ABI 1 does not cover every newer filesystem operation; the syscall
allowlist deliberately denies those operations independently. The profile is a
bounded in-memory fixture sandbox, not an arbitrary application/container runner
or a claim that an unknown host/kernel is secure.

Installation is explicit and does not launch anything:

```python
runtime = install_linux_vetted_runtime(
    private_owned_empty_directory,
    forbidden_roots=(authorized_fixture_parent, checkout_root),
    timeout_ms=1000,
    cpu_seconds=2,
    memory_mib=128,
)
```

The directory and base interpreter must be outside every excluded target and
enclosing Git worktree. The installed worker is an exact copy of the selected
package's standalone `_sandbox_worker.py`, hashed before and after use. Private
home remains fresh. The fixed allowlist is base Python with `-I -S -u`, that
worker and `--linux-isolated`; changed executable/worker/arguments are refused.
Limits are validated before installation writes any file.

The host reviews the exact `sandbox_test_action` and records actual approval
through its protected `HostEvidenceSource`. It then calls
`assess_linux_vetted_isolation(scope, source, profile, approval, runtime,
program, suite)`. This executes only a fixed owned benign probe, not the target
program. Successful kernel readback and enforcement probes issue an action-bound
`validation_isolation` assessment; failures or cancellation remain inconclusive.
Only a satisfied current assessment can authorize the one-use sandbox test scope.

```python
action = sandbox_test_action(runtime, program, suite, source)
# Called by the protected host only after actual review approval:
approval = source.record_approval(action, profile, receipt_id=review_receipt_id)
isolation = assess_linux_vetted_isolation(
    scope, source, profile, approval, runtime, program, suite
)
consent = authorize_sandbox_test(
    source, profile, approval, isolation, runtime, program, suite
)
run = run_sandbox_test(scope, source, runtime, program, suite, consent)
```

The actual run uses a separate Linux protocol and the versioned
`LinuxSandboxTestRun` contract. A completed result requires matched
`LinuxIsolationEvidence`: Landlock ABI, fixed filter digest, seccomp/no-new-privs
readback, hard limits, empty environment, pipe-only transport and actual denied
read/write-open/socket/fork/exec/memory-ceiling probes. The file probes use the
known owned worker itself and never modify it; networking stops at socket
creation and sends no request. No caller-supplied paths/programs are probed.
The existing parent deadline, output cap, cancellation, source/suite/configuration
digests and post-run drift checks remain mandatory.

Evidence decoded from JSON is inspection data. It cannot issue a protected
`LinuxSandboxTestRun`, host assessment, approval or execution grant. The legacy
`VettedSandboxRuntime`/v1 worker contract still accepts a separately protected
host-provided broker; it does not acquire an automatic Linux enforcement claim.

Native tests cover denied operations, environment/descriptor controls, syscall
profile/resource drift, one-use approval, cancellation, forged reply limits,
actual CPU hard termination and correct/ineffective/benign-breaking source fixes
under the kernel profile. These cover the exact canonical lexical predicate and
its declared version. Other source predicates, physical filesystem aliases,
arbitrary PoCs, live deployments and unsupported platforms remain outside that
evidence scope. Kernel compromise and malicious code in the protected host
process are outside this API trust boundary.

The dedicated authored `kernel-broker` CI job requires real primitive support
with `ORDIN_REQUIRE_LINUX_BROKER=1` on its Linux Python 3.10/3.13 matrix; unavailable
Landlock cannot silently skip its physical controls. Ordinary cross-platform
jobs retain explicit optional-platform skips. Authored configuration is not a
remote CI result.
