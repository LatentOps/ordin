"""Safe local adapter setup inventory. A manifest cannot install runtime authority."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from ordin._runtime_json import digest
from .adapters.contracts import PINS, coverage, installed_versions, require_framework_enabled
from ._reports import checked

MANIFEST = "ordin-swarm-framework.json"


def installation(framework):
    return checked(
        {
            "schema_version": "ordin.swarm_framework_installation.v1",
            "framework": framework,
            "tested_versions": PINS[framework],
            "manifest_only": True,
            "hook_installation": "in_process_host_required",
            "execution_authority": False,
        }
    )


def _directory(directory):
    candidate = Path(directory).absolute()
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError("explicit existing real installation directory required")
    return candidate.resolve(strict=True)


def setup(framework, *, directory, dry_run=True):
    if framework not in PINS or type(dry_run) is not bool:
        raise ValueError("supported explicit adapter and dry-run flag required")
    require_framework_enabled(framework)
    target = _directory(directory) / MANIFEST
    if target.exists() or target.is_symlink():
        raise ValueError("existing framework manifest is never overwritten")
    report = coverage(framework)
    if not report["compatible"]:
        raise ValueError("pinned framework dependencies missing or incompatible")
    payload = installation(framework)
    if not dry_run:
        raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode()
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    return checked(
        {
            "schema_version": "ordin.swarm_framework_setup.v1",
            "framework": framework,
            "dry_run": dry_run,
            "manifest_written": not dry_run,
            "manifest_digest": digest(payload),
            "runtime_installed": False,
            "execution_authority": False,
        }
    )


def uninstall(framework, *, directory, expected_digest):
    target = _directory(directory) / MANIFEST
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 8192:
        raise ValueError("original regular managed manifest required")
    value = json.loads(target.read_text())
    if value != installation(framework) or digest(value) != expected_digest:
        raise ValueError("changed or foreign manifest is never removed")
    current = target.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    ):
        raise ValueError("manifest changed during uninstall")
    target.unlink()
    return {"removed": True, "runtime_changed": False, "execution_authority": False}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ordin-swarm-adapter")
    parser.add_argument("operation", choices=("status", "doctor", "setup", "uninstall"))
    parser.add_argument("--framework", choices=tuple(PINS), default="custom")
    parser.add_argument("--directory")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--expected-digest")
    args = parser.parse_args(argv)
    try:
        if args.operation == "setup":
            if not args.directory or args.install and args.dry_run:
                raise ValueError("explicit directory and one setup mode required")
            report = setup(args.framework, directory=args.directory, dry_run=not args.install)
        elif args.operation == "uninstall":
            if not args.directory or not args.expected_digest:
                raise ValueError("explicit directory and original manifest digest required")
            report = uninstall(
                args.framework, directory=args.directory, expected_digest=args.expected_digest
            )
        else:
            report = coverage(args.framework)
            if args.operation == "doctor":
                report["diagnostics"].extend(
                    [
                        "native_runtime_not_bound",
                        "manifest_never_authorizes_execution",
                    ]
                )
                report["environment_compatible"] = (
                    report["compatible"]
                    and installed_versions(args.framework) == PINS[args.framework]
                )
        print(json.dumps(report, sort_keys=True))
        return 0 if args.operation != "doctor" or report["compatible"] else 1
    except (ValueError, OSError, KeyError) as error:
        print("Adapter setup refused: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
