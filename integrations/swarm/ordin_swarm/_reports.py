"""Data-only framework reports share Ordin's packaged schema validation."""

from ordin.schema import validate_named_schema


def checked(value):
    name = value["schema_version"].removeprefix("ordin.").removesuffix(".v1")
    if validate_named_schema(name, value):
        raise ValueError("invalid bounded framework report")
    return value
