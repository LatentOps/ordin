"""Optional explicit OpenShell integration; never imported by Ordin core."""

__version__ = "0.1.0"
TESTED_OPENSHELL_VERSION = "0.1.2"
POLICY_SCHEMA_VERSION = 1
PROVER_JSON_SCHEMA_VERSION = 1

from .compiler import OpenShellBackend, compile_openshell_policy

__all__ = ["OpenShellBackend", "compile_openshell_policy"]
