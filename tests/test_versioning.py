from importlib.metadata import version

import ordin


PUBLIC_RELEASE_VERSION = "0.1.0"
NEXT_DEVELOPMENT_VERSION = "0.2.0.dev0"


def test_runtime_version_matches_installed_distribution():
    assert ordin.__version__ == version("ordin")


def test_post_release_source_does_not_reuse_published_version():
    assert ordin.__version__ == NEXT_DEVELOPMENT_VERSION
    assert ordin.__version__ != PUBLIC_RELEASE_VERSION
    assert ".dev" in ordin.__version__
