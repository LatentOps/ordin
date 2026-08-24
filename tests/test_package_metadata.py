from importlib.metadata import version

import commandgraph


def test_runtime_version_matches_distribution_metadata():
    assert commandgraph.__version__ == version("commandgraph")
