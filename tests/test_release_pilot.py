"""Engineering harness tests never constitute elapsed-time pilot evidence."""

import json
from importlib import machinery
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import zipfile
import zipimport

import pytest

from scripts import run_release_pilot as pilot


def cleanup_module(kind):
    module = ModuleType("ordin_swarm.host_authority")
    module._HostCleanupIncomplete = kind
    return module


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
    monkeypatch.setattr(pilot, "_preimport_guard", lambda roots: None)
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
        cleanup_module(CleanupPending),
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
        cleanup_module(CleanupPending),
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
        cleanup_module(CleanupPending),
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


def standard_imports(monkeypatch):
    """Emulate only the standard machinery of a fresh private interpreter."""
    details = (
        (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
        (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES),
        (machinery.SourcelessFileLoader, machinery.BYTECODE_SUFFIXES),
    )
    monkeypatch.setattr(
        sys,
        "meta_path",
        [machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder],
    )
    monkeypatch.setattr(
        sys, "path_hooks", [zipimport.zipimporter, machinery.FileFinder.path_hook(*details)]
    )
    monkeypatch.setattr(sys, "path_importer_cache", {})
    for name in tuple(sys.modules):
        if name in {"ordin", "ordin_swarm"} or name.startswith(("ordin.", "ordin_swarm.")):
            monkeypatch.delitem(sys.modules, name)


def two_installed_packages(tmp_path, monkeypatch, *, tag=None):
    prefix = tmp_path / "fresh-environment"
    site = prefix / "Lib" / "site-packages"
    site.mkdir(parents=True)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    packages, artifacts = {}, {}
    for namespace, project in (("ordin", "ordin"), ("ordin_swarm", "ordin-swarm")):
        root = site / namespace
        root.mkdir()
        raw = b"# exact installed fixture, no execution side effects\n"
        (root / "__init__.py").write_bytes(raw)
        wheel = bundle / (namespace + "-0.4.0-py3-none-any.whl")
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(namespace + "/__init__.py", raw)
        packages[project] = {"version": "0.4.0", "wheel": wheel.name}
        artifacts[wheel.name] = pilot._sha(wheel)
    manifest = {"packages": packages, "artifacts": artifacts, "tag": tag}
    (bundle / "release.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(
        pilot.metadata,
        "distribution",
        lambda project: SimpleNamespace(
            version="0.4.0",
            read_text=lambda name: None,
            locate_file=lambda namespace: site / namespace,
        ),
    )
    monkeypatch.setattr(
        pilot,
        "_helper",
        lambda name: SimpleNamespace(verify_bundle=lambda *args, **kwargs: manifest),
    )
    monkeypatch.setattr(pilot, "_require_isolated", lambda: None, raising=False)
    monkeypatch.setattr(pilot, "_runtime_tooling", lambda: {"unit_fixture": True})
    standard_imports(monkeypatch)
    monkeypatch.setattr(sys, "path", [str(site), *sys.path])
    return bundle, site, manifest


def test_actual_source_import_spec_is_refused_without_executing_a_marker(tmp_path, monkeypatch):
    bundle, _, _ = two_installed_packages(tmp_path, monkeypatch)
    overlay = tmp_path / "owned-source-overlay"
    package = overlay / "ordin"
    package.mkdir(parents=True)
    marker = tmp_path / "source-code-executed.txt"
    (package / "__init__.py").write_text(
        "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n"
    )
    monkeypatch.setattr(sys, "path", [str(overlay), *sys.path])
    with pytest.raises(ValueError):
        pilot.run_pilot(
            bundle,
            tmp_path / "output",
            revision="a" * 40,
            tree="b" * 40,
            tag=None,
            config=pilot.PilotConfiguration(portable_only=True),
        )
    assert not marker.exists(), "source overlay executed before refusal"


@pytest.mark.parametrize(
    "overlay", ["loaded", "loaded_path_callback", "meta", "hook", "cache", "loader"]
)
def test_import_overlays_are_rejected_without_invoking_their_callbacks(
    tmp_path, monkeypatch, overlay
):
    bundle, site, _ = two_installed_packages(tmp_path, monkeypatch)
    marker = tmp_path / "import-callback-executed"

    class ForeignFinder:
        def find_spec(self, *args, **kwargs):
            marker.write_text("finder executed")
            return None

    def foreign_hook(*args):
        marker.write_text("path hook executed")
        raise ImportError

    if overlay in {"loaded", "loaded_path_callback"}:
        module = ModuleType("ordin")
        module.__file__ = str(tmp_path / "source/ordin/__init__.py")
        if overlay == "loaded_path_callback":

            class ForeignPath:
                def __fspath__(self):
                    marker.write_text("path callback executed")
                    return str(site / "ordin/__init__.py")

            module.__file__ = ForeignPath()
        module.__getattr__ = lambda name: marker.write_text("module callback executed")
        monkeypatch.setitem(sys.modules, "ordin", module)
    elif overlay == "meta":
        monkeypatch.setattr(sys, "meta_path", [ForeignFinder(), *sys.meta_path])
    elif overlay == "hook":
        monkeypatch.setattr(sys, "path_hooks", [foreign_hook, *sys.path_hooks])
    elif overlay == "cache":
        monkeypatch.setitem(sys.path_importer_cache, str(site), ForeignFinder())
    else:

        class ForeignLoader(machinery.SourceFileLoader):
            def __init__(self, *args):
                marker.write_text("foreign loader constructed")
                super().__init__(*args)

        finder = machinery.FileFinder(str(site), (ForeignLoader, machinery.SOURCE_SUFFIXES))
        monkeypatch.setitem(sys.path_importer_cache, str(site), finder)
    with pytest.raises(ValueError):
        pilot.run_pilot(
            bundle,
            tmp_path / "output",
            revision="a" * 40,
            tree="b" * 40,
            config=pilot.PilotConfiguration(portable_only=True),
        )
    assert not marker.exists() and not (tmp_path / "output").exists()


@pytest.mark.parametrize("tag", [None, "v0.4.0"])
def test_trusted_expected_tag_is_forwarded_unchanged_and_recorded(tmp_path, monkeypatch, tag):
    bundle, _, manifest = two_installed_packages(tmp_path, monkeypatch, tag=tag)
    calls = []

    def verify(*args, **kwargs):
        calls.append(kwargs)
        return manifest

    monkeypatch.setattr(pilot, "_helper", lambda name: SimpleNamespace(verify_bundle=verify))
    monkeypatch.setattr(
        pilot, "_run_verified", lambda *args, **kwargs: {"expected_tag": kwargs["expected_tag"]}
    )
    result = pilot.run_pilot(
        bundle,
        tmp_path / "output",
        revision="a" * 40,
        tree="b" * 40,
        tag=tag,
        config=pilot.PilotConfiguration(portable_only=True),
    )
    assert calls[0]["tag"] == tag == result["expected_tag"]


@pytest.mark.parametrize(
    "actual,expected", [(None, "v0.4.0"), ("v0.4.0", None), ("v0.4.1", "v0.4.0")]
)
def test_candidate_and_selected_tag_mismatch_never_reaches_runtime_imports(
    tmp_path, monkeypatch, actual, expected
):
    bundle, _, _ = two_installed_packages(tmp_path, monkeypatch, tag=actual)
    monkeypatch.setattr(
        pilot, "import_module", lambda name: pytest.fail("tag mismatch executed a runtime import")
    )
    with pytest.raises(ValueError, match="expected tag"):
        pilot.run_pilot(
            bundle,
            tmp_path / "output",
            revision="a" * 40,
            tree="b" * 40,
            tag=expected,
            config=pilot.PilotConfiguration(portable_only=True),
        )
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("isolated,bytecode", [(0, False), (0, True), (1, False)])
def test_cli_requires_both_isolation_and_disabled_bytecode_writes(monkeypatch, isolated, bytecode):
    monkeypatch.setattr(sys, "flags", SimpleNamespace(isolated=isolated))
    monkeypatch.setattr(sys, "dont_write_bytecode", bytecode)
    with pytest.raises(ValueError, match="-I -B"):
        pilot._require_isolated()


def test_stale_pyc_cannot_replace_verified_source_on_first_import(tmp_path, monkeypatch):
    import py_compile
    from importlib.util import cache_from_source

    bundle, site, manifest = two_installed_packages(tmp_path, monkeypatch)
    marker = tmp_path / "stale-bytecode-executed"
    source = site / "ordin/__init__.py"
    good = b"#" + b" verified fixture" * 256 + b"\n"
    source.write_bytes(good)
    evil = tmp_path / "compiled-data-only.py"
    bad = (
        "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n"
    ).encode()
    evil.write_bytes(bad + b"#" + b" " * (len(good) - len(bad) - 1))
    os.utime(evil, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
    py_compile.compile(str(evil), cfile=cache_from_source(str(source)), doraise=True)
    wheel = bundle / manifest["packages"]["ordin"]["wheel"]
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ordin/__init__.py", good)
    manifest["artifacts"][wheel.name] = pilot._sha(wheel)
    (bundle / "release.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(pilot, "_run_verified", lambda *args, **kwargs: {"expected_tag": None})
    prior = sys.pycache_prefix, sys.dont_write_bytecode
    pilot.run_pilot(
        bundle,
        tmp_path / "output",
        revision="a" * 40,
        tree="b" * 40,
        config=pilot.PilotConfiguration(portable_only=True),
    )
    assert not marker.exists()
    assert (sys.pycache_prefix, sys.dont_write_bytecode) == prior


@pytest.mark.parametrize("wrong", ["pytest", "packaging", "pluggy", None])
def test_runtime_lock_pins_applicable_tools_before_fixtures_and_records_canonical_hash(
    tmp_path, monkeypatch, wrong
):
    import hashlib

    directory = tmp_path / "requirements"
    directory.mkdir()
    text = "pytest==9.2.0 \\\n    --hash=sha256:111\npackaging==26.3 \\\n    --hash=sha256:222\npluggy==1.7.0 \\\n    --hash=sha256:333\n"
    (directory / "pilot-runtime.txt").write_bytes(text.replace("\n", "\r\n").encode())
    monkeypatch.setattr(pilot, "ROOT", tmp_path)
    versions = {"pytest": "9.2.0", "packaging": "26.3", "pluggy": "1.7.0"}
    monkeypatch.setattr(
        pilot.metadata, "version", lambda name: "wrong" if name == wrong else versions[name]
    )
    if wrong is None:
        result = pilot._runtime_tooling()
        assert result["versions"] == versions
        assert result["sha256"] == hashlib.sha256(text.encode()).hexdigest()
        assert result["hash_normalization"] == "UTF-8 LF"
    else:
        with pytest.raises(ValueError, match="tooling|dependency"):
            pilot._runtime_tooling()
