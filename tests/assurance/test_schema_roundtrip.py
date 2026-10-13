import json
from pathlib import Path

from ordin.assurance._schemas import SCHEMAS
from ordin.schema import SCHEMA_FILES, validate_instance, validate_schema_files

from .test_models import examples

ROOT = Path(__file__).resolve().parents[2]


def test_all_assurance_schemas_registered_packaged_and_byte_identical():
    assert validate_schema_files() == []
    for name, expected in SCHEMAS.items():
        filename = SCHEMA_FILES[name]
        source = ROOT / "schemas" / filename
        packaged = ROOT / "ordin/resources/schemas" / filename
        assert source.read_bytes() == packaged.read_bytes()
        assert json.loads(source.read_bytes()) == expected


def test_record_examples_match_shipped_schemas():
    for record in examples():
        payload = record.as_dict()
        assert validate_instance(payload, SCHEMAS[record.SCHEMA]) == []
        payload["trusted"] = True
        assert validate_instance(payload, SCHEMAS[record.SCHEMA])


def test_draft_authority_and_model_number_bounds_are_in_both_validators():
    records = examples()
    draft = records[1].as_dict()
    draft["authoritative"] = True
    assert validate_instance(draft, SCHEMAS[records[1].SCHEMA])
    model = records[9].as_dict()
    model["answers"][0]["p_yes"] = 1.1
    assert validate_instance(model, SCHEMAS[records[9].SCHEMA])
