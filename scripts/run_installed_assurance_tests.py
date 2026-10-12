"""Run CI fixtures with core and optional namespaces pinned to installed wheels."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

SUITES = {
    "core": (
        "tests/assurance",
        "tests/test_schemas.py",
        "tests/test_public_api.py",
        "tests/test_security_integrity.py",
        "tests/test_namespace_guard.py",
        "tests/test_docs_links.py",
        "tests/test_session.py",
    ),
    "decision_models": ("integrations/decision_models/tests",),
    "codex_security": (
        "tests/assurance/test_codex_import.py",
        "tests/assurance/test_sarif_import.py",
        "tests/assurance/test_codex_scanner.py",
        "tests/assurance/test_workflow_import.py",
    ),
    "solver": (
        "tests/assurance/test_solver.py",
        "tests/assurance/test_contract_coverage.py",
        "tests/assurance/test_schema_roundtrip.py",
        "tests/test_schemas.py",
    ),
    "kernel": ("tests/assurance/test_linux_sandbox.py",),
}


def pin_installed_namespace(name: str) -> Path:
    module = importlib.import_module(name)
    if module.__file__ is None:
        raise ValueError(f"{name} lacks an installed module origin")
    path = Path(module.__file__).resolve(strict=True)
    if not path.is_relative_to(Path(sys.prefix).resolve()) or not any(
        part in {"site-packages", "dist-packages"} for part in path.parts
    ):
        raise ValueError(f"{name} must be imported from an installed wheel")
    return path.parent


def check_loaded_namespaces(roots: dict[str, Path]) -> None:
    for name, module in tuple(sys.modules.items()):
        root = next(
            (
                path
                for namespace, path in roots.items()
                if name == namespace or name.startswith(namespace + ".")
            ),
            None,
        )
        if root is not None and module is not None:
            origin = getattr(module, "__file__", None)
            if origin is None or not Path(origin).resolve().is_relative_to(root):
                raise ValueError("tests loaded a source overlay into an installed namespace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=tuple(SUITES), required=True)
    parser.add_argument("--basetemp", type=Path, required=True)
    parser.add_argument("--junitxml", type=Path, required=True)
    args = parser.parse_args()
    roots = {"ordin": pin_installed_namespace("ordin")}
    if args.suite in {"decision_models", "codex_security"}:
        namespace = "ordin_" + args.suite
        roots[namespace] = pin_installed_namespace(namespace)
    import pytest

    result = pytest.main(
        [
            "-q",
            "-ra",
            "-p",
            "no:cacheprovider",
            "--basetemp=" + str(args.basetemp),
            "--junitxml=" + str(args.junitxml),
            *SUITES[args.suite],
        ]
    )
    check_loaded_namespaces(roots)
    return int(result)


if __name__ == "__main__":
    raise SystemExit(main())
