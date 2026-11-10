"""Run fixed installed-wheel engineering probes or an explicit elapsed-time pilot.

Run this exact-source helper with an isolated installed environment's Python -I.
No artifact, elapsed-time result or scripted review authorizes production work.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
import gc
import hashlib
from importlib import import_module, metadata, util
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MIN_PILOT_SECONDS = 3 * 86400
MAX_PILOT_SECONDS = 7 * 86400
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_CYCLE_BYTES = 128 * 1024 * 1024
FIXED_CASES = (
    "tests/test_swarm_coordinator.py::test_original_mtls_scope_one_use_dispatch_and_full_bound_accounting",
    "tests/test_swarm_coordinator.py::test_two_authenticated_hosts_cannot_reserve_past_shared_swarm_budget",
    "tests/test_swarm_coordinator_recovery.py::test_takeover_fences_old_owner_and_retains_uncertain_budget",
    "tests/test_swarm_coordinator_recovery.py::test_revocation_survives_restart_and_json_cannot_resume",
    "tests/test_swarm_coordinator_recovery.py::test_lost_forward_ack_never_calls_executor_or_refunds_hold",
    "tests/test_swarm_coordinator_recovery.py::test_epoch_change_during_backend_reconciliation_cannot_resume",
    "tests/test_swarm_coordinator_recovery.py::test_unknown_inflight_effect_cannot_resume_from_operator_boolean_or_json",
    "tests/test_swarm_budgets.py::test_persistent_recovery_fences_old_reserved_tickets_and_retains_forwarding_hold",
    "tests/test_swarm_budgets.py::test_policy_epoch_recovery_preserves_consumed_spend",
    "tests/test_swarm_budgets.py::test_physical_budget_requirement_cannot_be_satisfied_by_cost_estimate_or_json_flag",
)


@dataclass(frozen=True)
class PilotConfiguration:
    mode: str = "engineering"
    cycles: int = 2
    duration_seconds: int | None = None
    interval_seconds: int = 0
    portable_only: bool = False

    def __post_init__(self):
        if (
            type(self.mode) is not str
            or self.mode not in {"engineering", "pilot"}
            or type(self.cycles) is not int
            or not 1 <= self.cycles <= 16
            or type(self.interval_seconds) is not int
            or type(self.portable_only) is not bool
        ):
            raise ValueError("invalid bounded pilot configuration")
        if self.mode == "pilot":
            if (
                type(self.duration_seconds) is not int
                or not MIN_PILOT_SECONDS <= self.duration_seconds <= MAX_PILOT_SECONDS
                or not 300 <= self.interval_seconds <= 3600
                or self.portable_only
            ):
                raise ValueError(
                    "multi-day pilot requires explicit 3-7 day duration and Linux scope"
                )
        elif self.duration_seconds is not None or not 0 <= self.interval_seconds <= 60:
            raise ValueError("engineering runs cannot claim a multi-day duration")

    @property
    def maximum_cycles(self):
        return (
            math.ceil(self.duration_seconds / self.interval_seconds) + 1
            if self.mode == "pilot"
            else self.cycles
        )


class BoundedCapture(io.StringIO):
    def write(self, value):
        super().write(value[: max(0, 1048576 - self.tell())])
        return len(value)


def _helper(name):
    spec = util.spec_from_file_location(
        "ordin_release_pilot_" + name, ROOT / "scripts" / (name + ".py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("exact-source release helper unavailable")
    module = util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
        return digest.hexdigest()


def _installed_payload(namespace, wheel, version):
    distribution = metadata.distribution(namespace.replace("_", "-"))
    selected_root = Path(distribution.locate_file(namespace))
    if selected_root.is_symlink():
        raise ValueError("pilot installed namespace cannot be linked")
    root = selected_root.resolve(strict=True)
    prefix = Path(sys.prefix).resolve(strict=True)
    if "site-packages" not in root.parts or not root.is_relative_to(prefix):
        raise ValueError("pilot requires installed wheels without source or editable overlays")
    direct = distribution.read_text("direct_url.json")
    if (
        distribution.version != version
        or direct
        and json.loads(direct).get("dir_info", {}).get("editable")
    ):
        raise ValueError("pilot installed distribution version or editable origin differs")
    with zipfile.ZipFile(wheel) as archive:
        selected = {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith(namespace + "/") and not name.endswith("/")
        }
    installed = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("pilot installed namespace contains a link")
        if path.is_file():
            if "__pycache__" in path.parts:
                continue
            installed[namespace + "/" + path.relative_to(root).as_posix()] = _sha(path)
    if not selected or installed != selected:
        raise ValueError("pilot installed payload differs from verified wheel bytes")
    return root


def _loaded(roots):
    for name, module in tuple(sys.modules.items()):
        for namespace, root in roots.items():
            if module is not None and (name == namespace or name.startswith(namespace + ".")):
                filename = getattr(module, "__file__", None)
                if filename is None or not Path(filename).resolve().is_relative_to(root):
                    raise ValueError("pilot imported a source namespace overlay")


def _cleanup_error(failure):
    # Error handling must not import an optional runtime or replace an original
    # failure. A real cleanup owner can exist only after its class was loaded.
    module = sys.modules.get("ordin_swarm.host_authority")
    kind = getattr(module, "_HostCleanupIncomplete", None)
    return isinstance(kind, type) and isinstance(failure, kind)


def _write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    if len(raw) > 1048576:
        raise ValueError("pilot report exceeds its bounded size")
    temporary = path.parent / (path.name + ".next")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _journal(path, value):
    raw = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    descriptor = os.open(
        path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "ab") as stream:
        if os.fstat(stream.fileno()).st_size + len(raw) > MAX_LOG_BYTES:
            raise ValueError("pilot cycle journal exceeds its bound")
        stream.write(raw)


def _directory_identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino


def _remove_owned_cycle(path, output, identities):
    if (
        path.name != "cycle"
        or path.parent != output
        or path.is_symlink()
        or output.is_symlink()
        or path.resolve().parent != output.resolve()
        or (_directory_identity(output), _directory_identity(path)) != identities
    ):
        raise ValueError("pilot cleanup requires its original owned cycle directory")
    shutil.rmtree(path)


def _portable(fixtures, cycle):
    # These are immutable, versioned synthetic test programs. The fixtures use
    # original mTLS handles and durable stores, and explicitly inject lost ACKs.
    # They are not a physical process boundary or an imported authority report.
    import pytest

    counts = {"collected": 0, "passed": 0, "failed": 0, "skipped": 0}

    class Summary:
        def pytest_collection_finish(self, session):
            counts["collected"] = len(session.items)

        def pytest_runtest_logreport(self, report):
            if report.failed:
                counts["failed"] += 1
            elif report.skipped:
                counts["skipped"] += 1
            elif report.when == "call" and report.passed:
                counts["passed"] += 1

        def pytest_collectreport(self, report):
            if report.failed:
                counts["failed"] += 1

    captured = BoundedCapture()
    prior_autoload = os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    try:
        os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        with redirect_stdout(captured), redirect_stderr(captured):
            code = pytest.main(
                [
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--confcutdir=" + str(fixtures / "tests"),
                    "--basetemp=" + str(cycle / "pytest"),
                    *(str(fixtures / name) for name in FIXED_CASES),
                ],
                plugins=[Summary()],
            )
    finally:
        if prior_autoload is None:
            os.environ.pop("PYTEST_DISABLE_PLUGIN_AUTOLOAD", None)
        else:
            os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = prior_autoload
    return {
        "passed": int(code) == 0
        and counts
        == {"collected": len(FIXED_CASES), "passed": len(FIXED_CASES), "failed": 0, "skipped": 0},
        "counts": counts,
        "boundary": "owned_synthetic_mtls_and_durable_accounting",
        "physical_enforcement": False,
        "diagnostics_sha256": hashlib.sha256(captured.getvalue().encode()).hexdigest(),
    }


def _cycle(fixtures, output, config, roots):
    cycle = output / "cycle"
    cycle.mkdir(mode=0o700)
    identities = _directory_identity(output), _directory_identity(cycle)
    cleanup_safe = True
    try:
        result = {"portable": _portable(fixtures, cycle), "host": {"status": "not_requested"}}
        if not config.portable_only:
            if sys.platform != "linux":
                raise ValueError("full pilot requires actual supported Linux host execution")
            from ordin_swarm.host_evaluation import run_evaluation
            from ordin_swarm.pilot_workflow import run_owned_transitions

            host = run_evaluation(cycle / "managed-host")
            transitions = run_owned_transitions(cycle / "transitions")
            result["host"] = {
                "status": "completed" if host["passed"] and transitions["passed"] else "failed",
                "cases": len(host["cases"]) + len(transitions["cases"]),
                "passed": sum(case["passed"] for case in host["cases"])
                + sum(case["passed"] for case in transitions["cases"]),
                "boundary": "owned_linux_read_write_workers",
                "client_process_confinement": "not_established",
                "operator_mode": "scripted_fixture_exact_authenticated_review",
            }
        _loaded(roots)
        result["passed"] = result["portable"]["passed"] and (
            config.portable_only or result["host"]["status"] == "completed"
        )
        if (
            sum(path.stat().st_size for path in cycle.rglob("*") if path.is_file())
            > MAX_CYCLE_BYTES
        ):
            raise ValueError("pilot cycle storage bound exceeded")
        return result
    except BaseException as failure:
        # The foreground controller must retain this original retry capability.
        # Never remove its installation, resubmit an effect or stringify custody.
        cleanup_safe = not _cleanup_error(failure)
        raise
    finally:
        if cleanup_safe:
            _remove_owned_cycle(cycle, output, identities)


def _acceptance(config, *, elapsed, wall_elapsed, cycles, failed, canceled):
    window = (
        config.mode == "pilot"
        and elapsed >= config.duration_seconds
        and wall_elapsed >= config.duration_seconds
    )
    return {
        "engineering_passed": cycles > 0 and not failed and not canceled,
        "elapsed_pilot_window_satisfied": window and cycles >= 2 and not failed and not canceled,
        "operator_acceptance": "pending_independent_human_review",
        "production_rollout_authorized": False,
        "execution_authority": False,
    }


def _wait_until(deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1, remaining))


def run_pilot(bundle, output, *, revision, tree, tag, config):
    if not isinstance(config, PilotConfiguration) or not all(
        type(value) is str and re.fullmatch(r"[a-f0-9]{40}", value) for value in (revision, tree)
    ):
        raise ValueError("pilot requires exact independently selected revision/tree")
    if (
        not bundle.is_absolute()
        or not output.is_absolute()
        or output.exists()
        or output.is_symlink()
    ):
        raise ValueError("pilot requires an absolute bundle and NEW absolute output directory")
    if output.resolve().is_relative_to(ROOT.resolve()) or output.resolve().is_relative_to(
        bundle.resolve()
    ):
        raise ValueError("pilot output must be outside the source and release bundle")
    if any(parent.is_symlink() for parent in (output.parent, *output.parent.parents)):
        raise ValueError("pilot output ancestors must not be links")
    integrity = _helper("release_integrity")
    manifest = integrity.verify_bundle(
        bundle, source_root=ROOT, revision=revision, tag=tag, tree=tree
    )
    roots, wheels = {}, []
    for namespace, project in (("ordin", "ordin"), ("ordin_swarm", "ordin-swarm")):
        selected = manifest["packages"][project]
        wheel = bundle / selected["wheel"]
        roots[namespace] = _installed_payload(namespace, wheel, selected["version"])
        wheels.append(
            {
                "name": project,
                "filename": wheel.name,
                "sha256": _sha(wheel),
                "version": selected["version"],
            }
        )
        if wheels[-1]["sha256"] != manifest["artifacts"][wheel.name]:
            raise ValueError("pilot wheel changed after bundle verification")
    # A fresh private cache location prevents stale package .pyc files from
    # replacing the verified source bytes on the first runtime import.
    prior_cache, prior_bytecode = sys.pycache_prefix, sys.dont_write_bytecode
    sys.pycache_prefix, sys.dont_write_bytecode = str(output / "bytecode"), True
    try:
        for namespace in roots:
            import_module(namespace)
        return _run_verified(
            bundle,
            output,
            revision,
            tree,
            config,
            roots,
            wheels,
            expected_artifacts=manifest["artifacts"],
        )
    finally:
        sys.pycache_prefix, sys.dont_write_bytecode = prior_cache, prior_bytecode


def _run_verified(
    bundle, output, revision, tree, config, roots, wheels, *, expected_artifacts=None
):
    _loaded(roots)
    output.mkdir(mode=0o700)
    helper = _helper("check_swarm_release")
    archive = helper.git(ROOT, "archive", "--format=tar", revision, "--", "tests")
    fixtures = output / "fixtures"
    fixture_identity = helper.extract_test_fixtures(archive, fixtures)
    started_utc, started, cpu_start = (
        datetime.now(timezone.utc),
        time.monotonic(),
        time.process_time(),
    )
    completed, failed, canceled, pending_cleanup, active_failure = 0, False, False, False, None
    report = {
        "schema_version": "ordin.release_pilot.v1",
        "mode": config.mode,
        "revision": revision,
        "tree": tree,
        "bundle_manifest_sha256": _sha(bundle / "release.json"),
        "wheels": wheels,
        "bundle_artifacts": expected_artifacts,
        "fixture_archive": fixture_identity,
        "started_utc": started_utc.isoformat(),
        "requested_duration_seconds": config.duration_seconds,
        "interval_seconds": config.interval_seconds,
        "maximum_cycles": config.maximum_cycles,
        "platform": sys.platform,
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "python_implementation": sys.implementation.name,
        "controller_euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "package_origin": "verified_installed_core_and_swarm_wheels",
        "origin_authenticated_by_json": False,
        "physical_host_requested": not config.portable_only,
        "external_production_targets": False,
        "hosted_models_used": False,
        "raw_payloads_logged": False,
        "cycles_completed": 0,
        "cycles_started": 0,
        "status": "running",
        "cumulative_cases": 0,
        "elapsed_pilot_window_satisfied": False,
        "production_rollout_authorized": False,
        "execution_authority": False,
        "operator_acceptance": "pending_independent_human_review",
    }

    def unchanged_runtime():
        if _sha(bundle / "release.json") != report["bundle_manifest_sha256"]:
            raise ValueError("pilot bundle manifest changed during execution")
        for name, expected in (expected_artifacts or {}).items():
            if _sha(bundle / name) != expected:
                raise ValueError("pilot bundle artifact changed during execution")
        for namespace, selected in zip(roots, wheels):
            if (
                _installed_payload(namespace, bundle / selected["filename"], selected["version"])
                != roots[namespace]
            ):
                raise ValueError("pilot installed namespace changed during execution")
        _loaded(roots)

    try:
        for index in range(config.maximum_cycles):
            unchanged_runtime()
            report["cycles_started"] = index + 1
            cycle_start, cycle_cpu = time.monotonic(), time.process_time()
            result = _cycle(fixtures, output, config, roots)
            gc.collect()
            unchanged_runtime()
            if time.process_time() - cycle_cpu > 60:
                result["passed"] = False
            row = {
                "cycle": index + 1,
                "started_offset_seconds": cycle_start - started,
                "elapsed_seconds": time.monotonic() - cycle_start,
                **result,
            }
            _journal(output / "cycles.jsonl", row)
            completed += 1
            report["cycles_completed"] = completed
            report["cumulative_cases"] += result["portable"]["counts"]["collected"] + result[
                "host"
            ].get("cases", 0)
            _write(output / "pilot.json", report)
            if not result["passed"]:
                failed = True
                break
            if config.mode == "pilot" and time.monotonic() - started >= config.duration_seconds:
                break
            if index + 1 < config.maximum_cycles:
                _wait_until(cycle_start + config.interval_seconds)
    except KeyboardInterrupt:
        canceled = True
    except BaseException as failure:
        failed = True
        pending_cleanup = _cleanup_error(failure)
        active_failure = failure
        raise
    finally:
        try:
            ended = datetime.now(timezone.utc)
            elapsed = time.monotonic() - started
            wall = (ended - started_utc).total_seconds()
            report.update(
                ended_utc=ended.isoformat(),
                elapsed_seconds=elapsed,
                wall_elapsed_seconds=wall,
                controller_cpu_seconds=time.process_time() - cpu_start,
                status="cleanup_pending"
                if pending_cleanup
                else "canceled"
                if canceled
                else "failed"
                if failed
                else "completed",
                **_acceptance(
                    config,
                    elapsed=elapsed,
                    wall_elapsed=wall,
                    cycles=completed,
                    failed=failed,
                    canceled=canceled,
                ),
            )
            report["cycles_sha256"] = (
                _sha(output / "cycles.jsonl") if (output / "cycles.jsonl").exists() else None
            )
            _write(output / "pilot.json", report)
        except BaseException:
            if active_failure is not None:
                raise active_failure
            raise
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--mode", choices=("engineering", "pilot"), default="engineering")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--duration-seconds", type=int)
    parser.add_argument("--interval-seconds", type=int, default=0)
    parser.add_argument("--portable-only", action="store_true")
    parser.add_argument("--owned-fixture", action="store_true", required=True)
    args = parser.parse_args(argv)
    config = PilotConfiguration(
        args.mode, args.cycles, args.duration_seconds, args.interval_seconds, args.portable_only
    )
    report = run_pilot(
        args.bundle,
        args.output,
        revision=args.revision,
        tree=args.tree,
        tag=args.tag,
        config=config,
    )
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "status",
                    "mode",
                    "cycles_completed",
                    "elapsed_seconds",
                    "engineering_passed",
                    "elapsed_pilot_window_satisfied",
                    "operator_acceptance",
                    "production_rollout_authorized",
                )
            }
        )
    )
    return (
        0
        if report["engineering_passed"]
        and (config.mode == "engineering" or report["elapsed_pilot_window_satisfied"])
        else 2
    )


def entrypoint(argv=None):
    previous = {}
    try:
        for name in ("SIGINT", "SIGTERM"):
            number = getattr(signal, name, None)
            if number is not None:
                try:
                    previous[number] = signal.signal(
                        number, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt())
                    )
                except (OSError, ValueError):
                    pass
        try:
            return main(argv)
        except SystemExit:
            raise
        except BaseException as failure:
            if _cleanup_error(failure):
                # This is deliberately foreground custody, not a fabricated
                # timeout success. Retry cleanup only; never repeat a cycle.
                for number in previous:
                    try:
                        signal.signal(number, lambda *_: None)
                    except (OSError, ValueError):
                        pass
                while True:
                    try:
                        failure.retry_cleanup()
                        break
                    except (Exception, KeyboardInterrupt):
                        try:
                            time.sleep(0.25)
                        except KeyboardInterrupt:
                            pass
            elif not isinstance(failure, (ValueError, OSError, RuntimeError, KeyboardInterrupt)):
                raise
            print(
                json.dumps(
                    {
                        "status": "failed",
                        "reason_code": "pilot.command_did_not_complete",
                        "execution_authority": False,
                    }
                ),
                file=sys.stderr,
            )
            return 2
    finally:
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except (OSError, ValueError):
                pass


if __name__ == "__main__":
    raise SystemExit(entrypoint())
