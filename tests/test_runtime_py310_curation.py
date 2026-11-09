"""Pure actual selection/copy AST over tiny data fixtures, never a real prefix."""

import ast
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from ordin.swarm import confined_tests


def package_capture(version, distributions, selected):
    source = Path(confined_tests.__file__)
    tree = ast.parse(source.read_text(encoding="utf-8"))
    builder = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "build_python_runtime_catalog"
    )
    start = next(
        index
        for index, node in enumerate(builder.body)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "packages"
    )
    selected_nodes = builder.body[start : start + 3]
    assert isinstance(selected_nodes[1], ast.If) and isinstance(selected_nodes[2], ast.For)
    excluded = next(
        node
        for node in builder.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "excluded" for target in node.targets)
    )
    requested = []

    def distribution(name):
        requested.append(name)
        assert name in distributions, "curator attempted unlisted distribution discovery"
        return distributions[name]

    def add(name, path):
        # Original bounded regular-file reader; source bytes must never execute.
        selected[name] = confined_tests._source(path, 1024)

    namespace = {
        "sys": SimpleNamespace(version_info=version),
        "Path": Path,
        "importlib": SimpleNamespace(metadata=SimpleNamespace(distribution=distribution)),
        "pytest_distribution": distributions["pytest"],
        "os": confined_tests.os,
        "IGNORED_PROJECT": confined_tests.IGNORED_PROJECT,
        "FORBIDDEN_RUNTIME": confined_tests.FORBIDDEN_RUNTIME,
        "add": add,
    }
    exec(
        compile(ast.Module(body=[excluded, *selected_nodes], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    return requested


@pytest.mark.parametrize("version", [(3, 10), (3, 11), (3, 13)])
def test_explicit_curator_captures_required_original_typing_bytes_without_host_site_or_plugins(
    tmp_path, version
):
    site = tmp_path / "synthetic-installed-data"
    site.mkdir()
    modules = {
        "pytest": ("pytest", "_pytest"),
        "pluggy": ("pluggy",),
        "packaging": ("packaging",),
        "iniconfig": ("iniconfig",),
        "pygments": ("pygments",),
        "exceptiongroup": ("exceptiongroup",),
        "tomli": ("tomli",),
        "typing-extensions": ("typing_extensions",),
    }
    distributions, original = {}, {}
    for name, names in modules.items():
        base = site / name
        base.mkdir()
        for module in names:
            if module == "typing_extensions":
                source = base / (module + ".py")
                relative = "site/" + module + ".py"
            else:
                (base / module).mkdir()
                source = base / module / "__init__.py"
                relative = "site/" + module + "/__init__.py"
                (source.parent / "injected.pth").write_text(
                    "raise AssertionError('pth executed')\n"
                )
                (source.parent / "sitecustomize.py").write_text(
                    "raise AssertionError('customization executed')\n"
                )
            data = ("raise AssertionError('capture must not import " + module + "')\n").encode()
            source.write_bytes(data)
            original[relative] = data
        distributions[name] = SimpleNamespace(locate_file=lambda path, base=base: base / path)
    # These ambient host-site/project objects are deliberately not curated.
    (site / "unlisted_module.py").write_text("raise AssertionError('host site exposed')\n")
    (site / "ambient.pth").write_text("raise AssertionError('ambient pth executed')\n")
    (site / "entrypoint_plugin").mkdir()
    (site / "entrypoint_plugin" / "__init__.py").write_text(
        "raise AssertionError('plugin executed')\n"
    )
    selected: dict[str, bytes] = {}
    original_path = tuple(sys.path)
    requested = package_capture(version, distributions, selected)
    assert tuple(sys.path) == original_path
    expected = {
        key: value
        for key, value in original.items()
        if version < (3, 11)
        or not any(name in key for name in ("exceptiongroup", "tomli", "typing_extensions"))
    }
    assert selected == expected
    expected_distributions = ["pluggy", "packaging", "iniconfig", "pygments"]
    if version < (3, 11):
        expected_distributions += ["exceptiongroup", "tomli", "typing-extensions"]
    assert requested == expected_distributions
    assert all(
        name.startswith("site/") and not name.endswith(".pth") and "sitecustomize" not in name
        for name in selected
    )
    assert not any("unlisted" in name or "entrypoint_plugin" in name for name in selected)
    # The complete synthetic image fingerprint includes the exact selected
    # dependency bytes. Actual private pin/ownership validation is native-only.
    image = tmp_path / "synthetic-image"
    image.mkdir()
    for name, data in selected.items():
        path = image / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    records, contents = confined_tests._capture(image, 64, 16384, ignored=frozenset())
    assert contents == selected
    if version < (3, 11):
        typing = next(row for row in records if row[0] == "site/typing_extensions.py")
        assert typing[3] == hashlib.sha256(original[typing[0]]).hexdigest()
        assert confined_tests._tree_digest(records) != confined_tests._tree_digest(
            [row for row in records if row is not typing]
        )
