"""Engineering harness tests never constitute elapsed-time pilot evidence."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace
import zipfile

import pytest

from scripts import run_release_pilot as pilot


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": []},
        {"mode": "production"},
        {"cycles": True},
        {"cycles": 0},
        {"cycles": 17},
        {"interval_seconds": -1},
        {"interval_seconds": 61},
        {"duration_seconds": 259200},
        {"portable_only": 1},
        {"mode": "pilot"},
        {"mode": "pilot", "duration_seconds": 259199, "interval_seconds": 300},
        {"mode": "pilot", "duration_seconds": 604801, "interval_seconds": 300},
        {"mode": "pilot", "duration_seconds": True, "interval_seconds": 300},
        {"mode": "pilot", "duration_seconds": 259200, "interval_seconds": 299},
        {"mode": "pilot", "duration_seconds": 259200, "interval_seconds": 3601},
        {
            "mode": "pilot",
            "duration_seconds": 259200,
            "interval_seconds": 300,
            "portable_only": True,
        },
    ],
)
def test_short_unbounded_or_ambiguous_configuration_cannot_request_a_pilot(changes):
    with pytest.raises(ValueError):
        pilot.PilotConfiguration(**changes)


@pytest.mark.parametrize(
    "mode,seconds,wall,cycles,failed,canceled,expected",
    [
        ("engineering", 604800, 604800, 2, False, False, False),
        ("pilot", 10, 604800, 2, False, False, False),
        ("pilot", 604800, 10, 2, False, False, False),
        ("pilot", 259200, 259200, 1, False, False, False),
        ("pilot", 259200, 259200, 2, True, False, False),
        ("pilot", 259200, 259200, 2, False, True, False),
        ("pilot", 259200, 259200, 2, False, False, True),
    ],
)
def test_acceptance_requires_both_real_clocks_and_never_grants_operator_authority(
    mode, seconds, wall, cycles, failed, canceled, expected
):
    config = (
        pilot.PilotConfiguration()
        if mode == "engineering"
        else pilot.PilotConfiguration(mode="pilot", duration_seconds=259200, interval_seconds=900)
    )
    result = pilot._acceptance(
        config, elapsed=seconds, wall_elapsed=wall, cycles=cycles, failed=failed, canceled=canceled
    )
    assert result["elapsed_pilot_window_satisfied"] is expected
    assert result["operator_acceptance"] == "pending_independent_human_review"
    assert not result["execution_authority"] and not result["production_rollout_authorized"]


@pytest.mark.parametrize("duration", [259200, 604800])
def test_multi_day_work_count_is_bounded_without_starting_a_long_job(duration):
    config = pilot.PilotConfiguration(mode="pilot", duration_seconds=duration, interval_seconds=300)
    assert config.maximum_cycles <= 2017


def installed_fixture(tmp_path, monkeypatch):
    prefix = tmp_path / "environment"
    root = prefix / "Lib" / "site-packages" / "ordin"
    root.mkdir(parents=True)
    (root / "__init__.py").write_bytes(b"# verified package bytes\n")
    wheel = tmp_path / "ordin-0.4.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ordin/__init__.py", (root / "__init__.py").read_bytes())
    distribution = SimpleNamespace(
        version="0.4.0", read_text=lambda name: None, locate_file=lambda name: root
    )
    monkeypatch.setattr(pilot.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    return root, wheel, distribution


@pytest.mark.parametrize(
    "mutation", ["source", "version", "editable", "changed", "extra", "sourceless_cache"]
)
def test_source_wrong_version_editable_or_changed_installed_bytes_fail_before_import(
    tmp_path, monkeypatch, mutation
):
    root, wheel, distribution = installed_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        pilot, "import_module", lambda name: pytest.fail("unverified package executed")
    )
    if mutation == "source":
        foreign = tmp_path / "different-environment"
        foreign.mkdir()
        monkeypatch.setattr(sys, "prefix", str(foreign))
    elif mutation == "version":
        distribution.version = "0.3.0"
    elif mutation == "editable":
        distribution.read_text = lambda name: '{"dir_info":{"editable":true}}'
    elif mutation == "changed":
        (root / "__init__.py").write_bytes(b"raise AssertionError('tampered')")
    elif mutation == "extra":
        (root / "unpackaged.py").write_bytes(b"unreviewed = True")
    else:
        (root / "unpackaged.pyc").write_bytes(b"foreign cache bytes")
    with pytest.raises(ValueError):
        pilot._installed_payload("ordin", wheel, "0.4.0")


def test_exact_installed_payload_is_compared_without_importing_it(tmp_path, monkeypatch):
    root, wheel, _ = installed_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        pilot, "import_module", lambda name: pytest.fail("byte comparison executed code")
    )
    assert pilot._installed_payload("ordin", wheel, "0.4.0") == root


@pytest.mark.parametrize("name", ["different", "cycle"])
def test_cleanup_never_removes_foreign_or_replaced_directories(tmp_path, name):
    output = tmp_path / "owned"
    output.mkdir()
    cycle = output / name
    cycle.mkdir()
    sentinel = cycle / "preserved.txt"
    sentinel.write_text("preserved")
    identities = (pilot._directory_identity(output), (-1, -1))
    with pytest.raises(ValueError):
        pilot._remove_owned_cycle(cycle, output, identities)
    assert sentinel.read_text() == "preserved"


def test_cleanup_removes_only_the_original_owned_cycle(tmp_path):
    cycle = tmp_path / "cycle"
    cycle.mkdir()
    (cycle / "data").write_text("owned")
    pilot._remove_owned_cycle(
        cycle, tmp_path, (pilot._directory_identity(tmp_path), pilot._directory_identity(cycle))
    )
    assert not cycle.exists() and tmp_path.is_dir()


def test_journal_bound_is_enforced_before_append(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "MAX_LOG_BYTES", 3)
    path = tmp_path / "cycles.jsonl"
    with pytest.raises(ValueError, match="bound"):
        pilot._journal(path, {"cycle": 1})
    assert path.read_bytes() == b""


def test_bounded_capture_discards_payload_overflow():
    capture = pilot.BoundedCapture()
    assert capture.write("x" * 2000000) == 2000000
    assert len(capture.getvalue()) == 1048576


@pytest.mark.parametrize("samples,expected", [([2], []), ([0, 0.9, 1.1], [1, 0.1])])
def test_interval_wait_never_sleeps_with_a_negative_boundary_value(monkeypatch, samples, expected):
    values, sleeps = iter(samples), []
    monkeypatch.setattr(pilot.time, "monotonic", lambda: next(values))
    monkeypatch.setattr(pilot.time, "sleep", sleeps.append)
    pilot._wait_until(1)
    assert sleeps == pytest.approx(expected)


def fake_setup(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "release.json").write_text("{}")
    helper = SimpleNamespace(
        git=lambda *args: b"fixed archive",
        extract_test_fixtures=lambda *args: {"source": "test fixture only"},
    )
    monkeypatch.setattr(pilot, "_helper", lambda name: helper)
    monkeypatch.setattr(pilot, "_loaded", lambda roots: None)
    return bundle, tmp_path / "output"


def success():
    return {
        "passed": True,
        "portable": {"counts": {"collected": 10}, "passed": True},
        "host": {"status": "not_requested"},
    }


def test_two_short_cycles_record_actual_counters_and_never_qualify_days(tmp_path, monkeypatch):
    bundle, output = fake_setup(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(pilot, "_cycle", lambda *args: calls.append(True) or success())
    report = pilot._run_verified(
        bundle, output, "a" * 40, "b" * 40, pilot.PilotConfiguration(portable_only=True), {}, []
    )
    assert calls == [True, True]
    assert report["status"] == "completed" and report["cycles_completed"] == 2
    assert report["cumulative_cases"] == 20 and report["engineering_passed"]
    assert not report["elapsed_pilot_window_satisfied"]
    assert report["ended_utc"] >= report["started_utc"]
    assert len((output / "cycles.jsonl").read_text().splitlines()) == 2


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), RuntimeError("private fixture failure")])
def test_failed_or_canceled_cycle_stops_without_replaying_or_counting_unexecuted_cases(
    tmp_path, monkeypatch, failure
):
    bundle, output = fake_setup(tmp_path, monkeypatch)
    calls = []

    def cycle(*args):
        calls.append(True)
        raise failure

    monkeypatch.setattr(pilot, "_cycle", cycle)
    if isinstance(failure, KeyboardInterrupt):
        pilot._run_verified(
            bundle, output, "a" * 40, "b" * 40, pilot.PilotConfiguration(portable_only=True), {}, []
        )
    else:
        with pytest.raises(RuntimeError) as caught:
            pilot._run_verified(
                bundle,
                output,
                "a" * 40,
                "b" * 40,
                pilot.PilotConfiguration(portable_only=True),
                {},
                [],
            )
        assert caught.value is failure
    report = json.loads((output / "pilot.json").read_text())
    assert len(calls) == 1 and report["cycles_completed"] == report["cumulative_cases"] == 0
    assert not report["engineering_passed"] and not report["elapsed_pilot_window_satisfied"]
    assert "private fixture failure" not in (output / "pilot.json").read_text()


def test_cleanup_owner_survives_report_disk_failure_and_is_not_replayed(tmp_path, monkeypatch):
    bundle, output = fake_setup(tmp_path, monkeypatch)

    class CleanupPending(RuntimeError):
        pass

    owner = object()
    failure = CleanupPending("private original owner")
    failure.cleanup_owner = owner
    monkeypatch.setitem(
        sys.modules,
        "ordin_swarm.host_authority",
        SimpleNamespace(_HostCleanupIncomplete=CleanupPending),
    )

    def cycle(*args):
        raise failure

    monkeypatch.setattr(pilot, "_cycle", cycle)
    monkeypatch.setattr(pilot, "_write", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(CleanupPending) as caught:
        pilot._run_verified(
            bundle, output, "a" * 40, "b" * 40, pilot.PilotConfiguration(portable_only=True), {}, []
        )
    assert caught.value is failure and caught.value.cleanup_owner is owner


def test_entrypoint_retains_cleanup_owner_until_success_and_never_repeats_work(monkeypatch, capsys):
    calls, retries = [], []

    class CleanupPending(RuntimeError):
        def retry_cleanup(self):
            retries.append(True)
            if len(retries) == 1:
                raise OSError("private cleanup retry")

    failure = CleanupPending("private original owner")
    monkeypatch.setitem(
        sys.modules,
        "ordin_swarm.host_authority",
        SimpleNamespace(_HostCleanupIncomplete=CleanupPending),
    )

    def main(arguments):
        calls.append(arguments)
        raise failure

    monkeypatch.setattr(pilot, "main", main)
    monkeypatch.setattr(pilot.time, "sleep", lambda seconds: None)
    assert pilot.entrypoint(["fixed request"]) == 2
    assert calls == [["fixed request"]] and len(retries) == 2
    assert "private" not in capsys.readouterr().err


@pytest.mark.parametrize("pending", [False, True])
def test_cycle_cleanup_preserves_pending_original_owner_but_removes_closed_fixture(
    tmp_path, monkeypatch, pending
):
    class CleanupPending(RuntimeError):
        pass

    failure = CleanupPending("original owner") if pending else RuntimeError("closed failure")
    monkeypatch.setitem(
        sys.modules,
        "ordin_swarm.host_authority",
        SimpleNamespace(_HostCleanupIncomplete=CleanupPending),
    )

    def portable(*args):
        raise failure

    monkeypatch.setattr(pilot, "_portable", portable)
    with pytest.raises(type(failure)) as caught:
        pilot._cycle(
            tmp_path / "fixtures", tmp_path, pilot.PilotConfiguration(portable_only=True), {}
        )
    assert caught.value is failure
    assert (tmp_path / "cycle").exists() is pending


def test_bundle_mutation_between_cycles_stops_before_repeating_work(tmp_path, monkeypatch):
    bundle, output = fake_setup(tmp_path, monkeypatch)
    calls = []

    def cycle(*args):
        calls.append(True)
        (bundle / "release.json").write_text('{"changed":true}')
        return success()

    monkeypatch.setattr(pilot, "_cycle", cycle)
    with pytest.raises(ValueError, match="changed"):
        pilot._run_verified(
            bundle,
            output,
            "a" * 40,
            "b" * 40,
            pilot.PilotConfiguration(portable_only=True),
            {},
            [],
        )
    assert calls == [True]
    report = json.loads((output / "pilot.json").read_text())
    assert report["status"] == "failed" and not report["engineering_passed"]


def test_help_does_not_require_or_import_optional_host(capsys):
    with pytest.raises(SystemExit) as stopped:
        pilot.entrypoint(["--help"])
    assert stopped.value.code == 0
    assert "duration-seconds" in capsys.readouterr().out
