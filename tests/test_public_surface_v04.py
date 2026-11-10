"""Audit the v0.4 contract against shipped code without rewriting its v0.3 baseline."""

import ast
import hashlib
from importlib import import_module
import json
from pathlib import Path
import re

import ordin
from ordin.schema import SCHEMA_FILES
from scripts.release_integrity import RELEASE_CHECKS


ROOT = Path(__file__).resolve().parents[1]
RESOURCE = ROOT / "ordin/resources/public-surface-0.4.json"
SURFACE = json.loads(RESOURCE.read_text(encoding="utf-8"))


def declared_all(path):
    for node in ast.parse((ROOT / path).read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"missing explicit public export declaration: {path}")


def declared_scripts(path):
    # This repository declares script targets as plain string assignments.
    # Parse only that section, without installing/importing optional SDKs.
    text = (ROOT / path).read_text(encoding="utf-8")
    block = text.partition("[project.scripts]")[2].split("\n[", 1)[0]
    return {
        key.strip(): ast.literal_eval(value.strip())
        for line in block.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }


def test_v04_inventory_is_shipped_and_preserves_exact_v03_baseline():
    assert RESOURCE.read_bytes() == (ROOT / "data/public-surface-0.4.json").read_bytes()
    assert SURFACE["schema_version"] == "ordin.public_surface.v1"
    assert SURFACE["package_line"] == "0.4"
    previous = SURFACE["previous_inventory"]
    baseline = (ROOT / "ordin/resources" / previous["file"]).read_bytes()
    assert baseline == (ROOT / "data" / previous["file"]).read_bytes()
    # Git checkouts may translate CRLF; compare the unchanged repository LF bytes.
    assert previous["sha256_lf"] == (
        "22ce430682b635f084f835b3a732ac2b6414055136bff1aa32d4c51ac6ea6eb0"
    )
    assert hashlib.sha256(baseline.replace(b"\r\n", b"\n")).hexdigest() == previous["sha256_lf"]
    old = json.loads(baseline)
    assert set(old["exports"]) <= set(SURFACE["exports"])
    assert {name: SURFACE["console_scripts"][name] for name in old["console_scripts"]} == (
        old["console_scripts"]
    )
    for module, names in old["module_contracts"].items():
        assert set(names) <= set(SURFACE["module_contracts"][module])
    for name, contract in old["schemas"].items():
        assert SURFACE["schemas"][name] == contract


def test_current_root_exports_have_explicit_stability_and_actual_implementations():
    assert sorted(ordin.__all__) == SURFACE["exports"]
    assert len(ordin.__all__) == len(set(ordin.__all__))
    assert set(SURFACE["export_status"]) == set(ordin.__all__)
    assert set(SURFACE["export_status"].values()) == {"supported", "experimental"}
    assert all(hasattr(ordin, name) for name in ordin.__all__)
    assert SURFACE["export_status"]["Ordin"] == "supported"
    assert SURFACE["export_status"]["RuntimeEvidenceSource"] == "experimental"


def test_registered_schema_inventory_is_complete_without_promoting_private_formats():
    assert {name: item["file"] for name, item in SURFACE["schemas"].items()} == SCHEMA_FILES
    assert {item["status"] for item in SURFACE["schemas"].values()} == {
        "stable-v1",
        "experimental",
    }
    assert SURFACE["schemas"]["swarm_context"]["status"] == "experimental"
    assert SURFACE["schemas"]["cursor_mcp_map"]["status"] == "stable-v1"


def test_all_five_distribution_entrypoint_sets_match_source_metadata():
    assert set(SURFACE["distributions"]) == {
        "ordin",
        "ordin-swarm",
        "ordin-runtime",
        "ordin-security",
        "ordin-decision-models",
    }
    for package in SURFACE["distributions"].values():
        assert package["console_scripts"] == declared_scripts(package["metadata"])
    assert SURFACE["console_scripts"] == declared_scripts("pyproject.toml")
    assert set(SURFACE["entrypoint_status"]) == set(SURFACE["console_scripts"])
    assert SURFACE["distributions"]["ordin-swarm"]["console_scripts"]["ordin-swarm-host"] == (
        "ordin_swarm.host_cli:entrypoint"
    )


def test_documented_module_exports_are_complete_and_classified():
    assert set(SURFACE["module_contracts"]) == set(SURFACE["module_status"])
    for module, path in SURFACE["declared_export_modules"].items():
        assert SURFACE["module_contracts"][module] == sorted(declared_all(path))
        assert SURFACE["module_status"][module] == "experimental"
    for module in ("ordin.cursor", "ordin.hermes", "ordin.mcp_proxy", "ordin.mcp_http"):
        loaded = import_module(module)
        assert all(hasattr(loaded, name) for name in SURFACE["module_contracts"][module])
        assert SURFACE["module_status"][module] == "supported"
    assert SURFACE["integration_status"]["crewai"]["status"] == "quarantined"


def test_current_candidate_guide_matches_real_job_count_and_prepublication_scope():
    guide = (ROOT / "docs/release-candidate-gate.md").read_text(encoding="utf-8")
    count = re.search(r"Require all (\d+) maintained main jobs", guide)
    assert count is not None and int(count[1]) == len(RELEASE_CHECKS)
    assert "`0.4.0`" in guide and "`0.3.0`" not in guide
    assert "actual elapsed pilot window" in guide
    quickstart = (ROOT / "docs/quickstart-0.4.md").read_text(encoding="utf-8")
    assert "--no-index --find-links" in quickstart
    assert "ordin==0.4.0 ordin-swarm==0.4.0" in quickstart
    assert "physical_enforcement: false" in quickstart
