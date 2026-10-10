"""Read pinned provisional workload artifacts without importing or running target code."""

import hashlib
from pathlib import Path

from ordin.assurance._files import read_scoped_file
from ordin.assurance._json import freeze, loads, validate

from .evaluation import SemanticCorpus, assert_disjoint


def load_frozen_workload(root: Path, *, expected_manifest_sha256: str):
    """Verify bytes, schema/partition/counts and content overlap; hashes do not certify labels."""
    validate(
        "assurance_authority_ref",
        {"authority_id": "semantic-workload", "boundary_digest": expected_manifest_sha256},
    )
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("frozen workload requires an explicit absolute directory")
    raw = read_scoped_file(root, "manifest.json", maximum=65536)
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("frozen workload manifest hash changed")
    manifest = loads(raw)
    if (
        set(manifest)
        != {
            "schema_version",
            "provisional",
            "artifacts",
            "case_count",
            "provenance",
            "source_permissions",
            "label_protocol",
            "supported_coverage",
            "excluded_coverage",
            "acceptance_eligible",
        }
        or manifest["schema_version"] != "ordin.semantic_workload_manifest.v1"
        or manifest["provisional"] is not True
        or manifest["acceptance_eligible"] is not False
        or not isinstance(manifest["artifacts"], list)
        or len(manifest["artifacts"]) != 3
        or type(manifest["case_count"]) is not int
        or not isinstance(manifest["label_protocol"], dict)
        or manifest["label_protocol"].get("independent_adjudication") is not False
    ):
        raise ValueError("unsupported provisional workload manifest")
    corpora, partitions = [], set()
    for artifact in manifest["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or set(artifact)
            != {
                "path",
                "sha256",
                "corpus_digest",
                "schema_version",
                "partition",
                "cases",
                "labels",
                "families",
            }
            or not isinstance(artifact["partition"], str)
            or artifact["partition"] not in {"development", "held_out", "adversarial_shift"}
            or artifact["partition"] in partitions
            or artifact["path"] != artifact["partition"] + ".json"
            or artifact["schema_version"] != "ordin.semantic_corpus.v1"
            or type(artifact["cases"]) is not int
            or not isinstance(artifact["labels"], dict)
            or set(artifact["labels"]) != {"harmful", "benign", "ambiguous"}
            or any(type(count) is not int for count in artifact["labels"].values())
            or not isinstance(artifact["families"], list)
            or any(not isinstance(family, str) for family in artifact["families"])
        ):
            raise ValueError("frozen workload artifact malformed")
        raw = read_scoped_file(root, artifact["path"], maximum=262144)
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            raise ValueError("frozen workload artifact hash changed")
        corpus = SemanticCorpus.from_dict(loads(raw))
        labels = {
            label: sum(case.label == label for case in corpus.cases)
            for label in ("harmful", "benign", "ambiguous")
        }
        if (
            corpus.partition != artifact["partition"]
            or corpus.digest != artifact["corpus_digest"]
            or len(corpus.cases) != artifact["cases"]
            or labels != artifact["labels"]
            or sorted({case.family for case in corpus.cases}) != artifact["families"]
        ):
            raise ValueError("frozen workload content does not match manifest")
        partitions.add(corpus.partition)
        corpora.append(corpus)
    assert_disjoint(*corpora)
    if sum(len(corpus.cases) for corpus in corpora) != manifest["case_count"]:
        raise ValueError("frozen workload case total differs")
    for index, corpus in enumerate(corpora):
        for other in corpora[index + 1 :]:
            if {case.family for case in corpus.cases} & {case.family for case in other.cases}:
                raise ValueError("provisional workload families overlap across partitions")
    return freeze(manifest), tuple(corpora)
