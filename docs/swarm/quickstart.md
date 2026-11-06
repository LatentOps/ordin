# Offline two-agent quickstart

This fixture needs the core and optional base adapter wheels. It downloads no
model, uses no provider key, starts no coordinator and blocks runtime network
connections. Prepare the wheels with the repository's pinned development tools
before moving them into an offline environment:

```console
python -m build --wheel --outdir dist
python -m build --wheel --outdir dist integrations/swarm
python -m venv .swarm-demo
```

Use `.swarm-demo/bin/python` on POSIX or `.swarm-demo\Scripts\python.exe` on
Windows for the following commands:

```console
python -m pip install --no-index --no-deps --find-links dist ordin ordin-swarm
python -I -m ordin_swarm.quickstart
```

The first stage reviews benign and unsafe proposals for two enrolled actors
without invoking a callback. The shadow stage compares review dispositions
without forwarding anything. The maintained custom-runtime stage performs a
permitted local read and protected private handoff, then refuses the egress and
child-creation callbacks. Its inherited labels and correlated outcomes come
from the original host gateways.

The JSON report uses `ordin.swarm_quickstart.v1`. It marks its labels as synthetic
fixture definitions, host callback mediation as the execution boundary and
physical enforcement as `false`. Its runtime-enforcement result is
`not_evaluated`. These are different results: a refused mediated callback does
not establish OS confinement or effectiveness against a real model.

Direct host tools, raw host networking, existing credentials and unwrapped
processes remain listed as uncovered. The fixture does not attempt a harmful
shell command on the host; those strings are reviewed as data. Run this fixture
as a standalone process, because its temporary network guard is deliberately
scoped to that fixture process.

The framework-specific example remains available through
`examples/swarm/framework_adapter_demo.py`. It needs only the selected pinned SDK
extra; the custom quickstart needs none. See [framework conformance](framework-adapters.md)
for tested versions and explicit asynchronous/background/direct-call gaps.

Windows can validate the offline host-control fixture. The owned kernel worker
requires supported Linux x86_64 Landlock/seccomp controls and has a separate
canary procedure. An unsupported host must return non-success, rather than
substituting a callback and labeling it physically enforced.

## Separate owned Linux broker canary

On a supported Linux x86_64 host, use the same isolated wheel environment:

```console
python -I -m ordin_swarm.owned_demo --owned-fixture
```

This creates its own private temporary workspace and original authenticated
parent/child/broker objects. It uses public fixture certificates only over local
socket pairs; it installs no trust root and starts no listening server. Those
certificates are test data and must not be used as production trust material.

The canary verifies an original allowed read and actual fresh-worker kernel
outcome. It separately checks a refused out-of-scope broker request, one-use
replay rejection and stale-epoch refusal. A direct host read of an owned canary
is reported as an uncovered successful bypass. The denied broker request is
identified as refused before the worker; it is not mislabeled as an observed
kernel denial.

`ordin.swarm_owned_demo.v1` marks physical enforcement only for the exact fresh
read worker, while keeping whole-host enforcement false. The fixture exercises
local delegation/admission accounting, not PostgreSQL consensus or production
routing. Missing host/kernel support returns non-success. A failed or incomplete
fixture cannot substitute a callback and claim a successful runtime result.
