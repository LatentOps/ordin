from ordin.assurance._schemas import SCHEMAS
from ordin.schema import validate_named_schema

from .contract_examples import assurance_contract_examples


def test_every_assurance_schema_has_a_valid_runtime_or_data_example(tmp_path):
    samples = assurance_contract_examples(tmp_path)
    assert set(samples) == set(SCHEMAS)
    for name, payload in samples.items():
        assert validate_named_schema(name, payload) == [], name
