"""Installed-only negative gate; never install or import the blocked SDK."""

import builtins
from contextlib import redirect_stdout
from importlib.metadata import metadata
from importlib.util import find_spec
from io import StringIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


def main():
    assert all(find_spec(name) is None for name in ("crewai", "crewai_core", "chromadb"))
    import ordin_swarm
    from ordin_swarm.adapters import CrewAIAdapter
    from ordin_swarm.adapters import contracts
    from ordin_swarm.cli import main as cli, setup
    from ordin_swarm.demo import run

    assert Path(ordin_swarm.__file__).is_relative_to(Path(sys.prefix))
    assert "crewai" not in (metadata("ordin-swarm").get_all("Provides-Extra") or [])
    original = builtins.__import__

    def no_blocked_import(name, *args, **kwargs):
        if name.split(".")[0] in {"crewai", "crewai_core", "chromadb"}:
            raise AssertionError("blocked SDK import attempted")
        return original(name, *args, **kwargs)

    with TemporaryDirectory(prefix="ordin-crewai-quarantine-") as name:
        directory = Path(name)
        with (
            patch("builtins.__import__", no_blocked_import),
            patch.object(
                contracts, "version", lambda distribution: contracts.PINS["crewai"][distribution]
            ),
        ):
            uninitialized = object.__new__(CrewAIAdapter)
            for operation in (
                lambda: contracts.require_version("crewai"),
                lambda: CrewAIAdapter(None, None, operator=object()),
                lambda: uninitialized.install(None, None, []),
                lambda: uninitialized._before(None),
                lambda: uninitialized.close(),
                lambda: setup("crewai", directory=directory, dry_run=False),
                lambda: run("crewai"),
            ):
                try:
                    operation()
                except ValueError as error:
                    assert "security_blocked" in str(error)
                else:
                    raise AssertionError("quarantined integration was enabled")
            assert list(directory.iterdir()) == []
            assert uninitialized.status()["availability"] == "security_blocked"
            report = contracts.coverage("crewai", installed=True, connected=True)
            assert report["availability"] == "security_blocked"
            assert not report["compatible"] and not report["connected"] and not report["installed"]
            assert report["covered"] == []
            output = StringIO()
            with redirect_stdout(output):
                assert cli(["doctor", "--framework", "crewai"]) == 1
            assert not json.loads(output.getvalue())["environment_compatible"]
    print("CrewAI security quarantine passed: SDK absent; matching external version still refused")


if __name__ == "__main__":
    main()
