from importlib.metadata import version

import ordin


def test_runtime_version_matches_distribution_metadata():
    assert ordin.__version__ == version("ordin")
