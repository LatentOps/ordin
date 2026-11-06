"""Optional SDK dependencies must not shadow Ordin's installed schema resources."""

from pathlib import Path
import runpy
import shutil

import ordin.schema as schemas


def test_foreign_sibling_schema_directory_cannot_shadow_owned_resources(tmp_path):
    package = tmp_path / "site-packages" / "ordin"
    owned = package / "resources" / "schemas"
    owned.mkdir(parents=True)
    source = Path(schemas.__file__)
    shutil.copyfile(source, package / "schema.py")
    name = schemas.SCHEMA_FILES["temporal_policy_set"]
    shutil.copyfile(schemas.PACKAGE_SCHEMA_DIR / name, owned / name)
    foreign = package.parent / "schemas"
    foreign.mkdir()
    (foreign / name).write_text('{"foreign":"schema from another distribution"}')
    isolated = runpy.run_path(str(package / "schema.py"), run_name="ordin.schema")
    assert isolated["SCHEMA_DIR"] == owned
    assert isolated["load_schema"]("temporal_policy_set") == schemas.load_schema(
        "temporal_policy_set"
    )
