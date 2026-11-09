"""Optional explicit Ordin Runtime integration; never imported by Ordin core."""

__version__ = "0.1.0"
TESTED_UPSTREAM_VERSION = "0.1.2"
POLICY_SCHEMA_VERSION = 1
PROVER_JSON_SCHEMA_VERSION = 1

from .compiler import OrdinRuntimeBackend, compile_runtime_policy

__all__ = ["OrdinRuntimeBackend", "compile_runtime_policy"]
