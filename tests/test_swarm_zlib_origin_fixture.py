"""The original native project's origin assertion, exercised without a worker."""

import ast
from importlib.machinery import BuiltinImporter, ExtensionFileLoader
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def origin_check():
    source = Path(__file__).with_name("test_swarm_confined_tests.py")
    tree = ast.parse(source.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_ZLIB_ORIGIN_ASSERTIONS"
            for target in node.targets
        )
    )
    native_test = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name
        == "test_pinned_framework_outranks_real_project_pytest_py_and_private_package_shadows"
    )
    project_source = next(
        node.args[0]
        for node in ast.walk(native_test)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "write_text"
    )
    assert any(
        isinstance(node, ast.Name) and node.id == "_ZLIB_ORIGIN_ASSERTIONS"
        for node in ast.walk(project_source)
    )
    fragment = ast.literal_eval(assignment.value)
    # Validate the complete original generated project too, without importing
    # its framework, constructing a runner, or executing any project code.
    generated = eval(
        compile(ast.Expression(project_source), str(source), "eval"),
        {
            "__builtins__": {},
            "_ZLIB_ORIGIN_ASSERTIONS": fragment,
            "selected": "/pinned/site",
            "route": SimpleNamespace(runtime=SimpleNamespace(pytest_version="9.2.0")),
        },
    )
    compile(generated, "original-generated-project", "exec")
    return compile(dedent(fragment), str(source), "exec")


def check_origin(code, module, *, builtins=("zlib",)):
    exec(
        code,
        {
            "zlib": module,
            "Path": Path,
            "__file__": str(Path("/project/test_sample.py").absolute()),
            "BuiltinImporter": BuiltinImporter,
            "ExtensionFileLoader": ExtensionFileLoader,
            "sys": SimpleNamespace(builtin_module_names=builtins),
        },
    )


def builtin_module(**fields):
    return SimpleNamespace(
        __spec__=SimpleNamespace(name="zlib", origin="built-in", loader=BuiltinImporter), **fields
    )


def extension_module(path=None, *, origin=None, loader=True, name="zlib"):
    path = str(Path("/trusted/lib-dynload/zlib.so").absolute()) if path is None else path
    return SimpleNamespace(
        __file__=path,
        __spec__=SimpleNamespace(
            name=name,
            origin=path if origin is None else origin,
            loader=ExtensionFileLoader("zlib", path) if loader else None,
        ),
    )


def test_original_fragment_accepts_verified_builtin_without_a_file(origin_check):
    module = builtin_module()
    check_origin(origin_check, module)
    # The previous native assertion fails for the actual diagnosed module shape.
    with pytest.raises(AttributeError):
        check_origin(
            compile(
                "assert not Path(zlib.__file__).is_relative_to(Path(__file__).parent)",
                "previous-native-assertion",
                "exec",
            ),
            module,
        )


def test_original_fragment_accepts_external_extension(origin_check):
    check_origin(origin_check, extension_module())


@pytest.mark.parametrize(
    "module",
    [
        builtin_module(__file__=None),
        SimpleNamespace(__spec__=SimpleNamespace(name="zlib", origin="built-in", loader=None)),
        SimpleNamespace(
            __spec__=SimpleNamespace(name="other", origin="built-in", loader=BuiltinImporter)
        ),
        extension_module(str(Path("/project/zlib.so").absolute())),
        extension_module("relative-zlib.so"),
        extension_module(origin="unknown"),
        extension_module(loader=False),
        extension_module(name="other"),
        SimpleNamespace(__spec__=SimpleNamespace(name="zlib", origin=None, loader=None)),
        SimpleNamespace(
            __file__=str(Path("/trusted/lib-dynload/zlib.so").absolute()),
            __spec__=SimpleNamespace(
                name="zlib",
                origin=None,
                loader=ExtensionFileLoader("zlib", "/trusted/lib-dynload/zlib.so"),
            ),
        ),
        SimpleNamespace(
            __file__=None, __spec__=SimpleNamespace(name="zlib", origin=None, loader=None)
        ),
        SimpleNamespace(__spec__=None),
    ],
)
def test_original_fragment_rejects_project_or_unverified_origin(origin_check, module):
    with pytest.raises((AssertionError, AttributeError)):
        check_origin(origin_check, module)


def test_builtin_claim_without_builtin_membership_is_rejected(origin_check):
    with pytest.raises(AssertionError):
        check_origin(origin_check, builtin_module(), builtins=())
