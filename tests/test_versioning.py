from importlib.metadata import version
from importlib import import_module
from pathlib import Path
import sys

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

import ordin


LAST_PUBLISHED_VERSION = "0.3.0"


def test_runtime_version_matches_installed_distribution():
    assert ordin.__version__ == version("ordin")


def test_post_release_source_does_not_reuse_published_version():
    current = Version(ordin.__version__)
    previous = Version(LAST_PUBLISHED_VERSION)
    assert str(current) == ordin.__version__
    assert len(current.release) == 3
    assert current.release > previous.release
    assert current.pre is None
    assert current.post is None
    assert current.local is None


def test_final_v04_source_versions_and_companion_bounds_are_coherent():
    tomllib = import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
    root = Path(__file__).resolve().parents[1]

    def project(relative):
        return tomllib.loads((root / relative / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]

    core = project(".")
    assert core["version"] == ordin.__version__
    assert project("integrations/swarm")["version"] == core["version"]
    for directory in ("swarm", "runtime", "security", "decision_models"):
        metadata = project("integrations/" + directory)
        assert len(metadata["dependencies"]) == 1
        requirement = Requirement(metadata["dependencies"][0])
        assert (
            requirement.name == "ordin" and requirement.marker is None and requirement.url is None
        )
        assert requirement.specifier == SpecifierSet(">=0.4.0,<0.5")
        assert requirement.specifier.contains(core["version"], prereleases=True)
        assert not requirement.specifier.contains("0.4.0.dev0", prereleases=True)
        assert not requirement.specifier.contains("0.5.0.dev0", prereleases=True)
        assert not requirement.specifier.contains("0.5.0", prereleases=True)
        if directory != "swarm":
            assert metadata["version"] == "0.1.0"
