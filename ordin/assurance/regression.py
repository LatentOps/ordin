"""Reviewed, new-file-only boundary regressions; never execution authority.

Transport/authority/provider fixtures cannot be losslessly reconstructed as
core-only action traces. This corpus retains the original closed generator,
failure, benign counterpart and review binding instead. No target programs run.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import posixpath
import re

from ordin import ActionEnvelope
from ordin._runtime_json import digest as core_digest
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import _safe_path
from ordin.runtime_observation import RuntimeEvidenceSource

from ._files import _directory, _identity, _safe_stat, directory_entries, read_scoped_file
from ._json import canonical_json, digest, freeze, loads, validate
from .challenge import _input, _outcome, replay_counterexample
from .host import HostApproval, HostEvidenceSource
from .models import ApprovedSecurityProfile, CounterexampleRecord, JsonRecord, RepositoryScope
from ._property_challenges import fixture_packet, outcome
from . import _optional_challenges as optional

MAX_CASES = 128
MAX_CASE_BYTES = 65536
_BENIGN = {
    "monotonicity": "allow_add_ask",
    "exact_request_commitment": "graphql_same",
    "protocol_separation": "rest_same",
    "tool_identity": "same",
    "history_observations": "valid",
    "delegation_subset": "filesystem_same",
    "trust_origin": "weak_roundtrip",
    "review_to_use_binding": "same",
}


def _reproducer_digest(generator):
    # A compatibility pin for the closed reproducer implementation, not a
    # signature/attestation for the entire host or an arbitrary repository.
    names = (
        "challenge.py",
        "property_challenge.py",
        "_property_challenges.py",
        "_optional_challenges.py",
        "regression.py",
    )
    root = Path(__file__).parent
    files = {name: hashlib.sha256(read_scoped_file(root, name)).hexdigest() for name in names}
    if generator == optional.VERSION:
        import importlib.util

        selected = importlib.util.find_spec("ordin_decision_models")
        if selected is None or selected.origin is None:
            raise ValueError("optional regression reproducer is unavailable")
        package = Path(selected.origin).parent
        for name in ("routing.py", "mock.py", "protocol.py", "privacy.py", "fusion.py"):
            files["optional/" + name] = hashlib.sha256(read_scoped_file(package, name)).hexdigest()
    return digest("boundary_reproducer_manifest", files)


def _benign_capture(record):
    if record.generator_version == "authority-paths-v1":
        failed = loads(record.minimized_input)
        packet = _input("/fixture/benign", failed["variant"])
        expected, actual, status = _outcome(packet)
        if status != "evaluated" or expected != actual:
            raise ValueError("benign authority counterpart is unresolved")
        return canonical_json(packet), expected
    failed = loads(record.minimized_input)["fixture"]
    if record.generator_version == optional.VERSION:
        packet = optional.fixture_packet(
            optional.PROPERTY, "benign_supported", failed["value"], failed["variant"], noise=False
        )
        checked = optional.outcome(packet)
    elif (
        record.generator_version == "security-properties-v1" and record.claimed_property in _BENIGN
    ):
        packet = fixture_packet(
            record.claimed_property,
            _BENIGN[record.claimed_property],
            failed["value"],
            failed["variant"],
            noise=False,
        )
        checked = outcome(packet)
    else:
        raise ValueError("no closed benign counterpart for this generator/property")
    if not checked.assessable or checked.expected != checked.actual or not checked.benign:
        raise ValueError("benign property counterpart is unresolved")
    return canonical_json(
        {
            "fixture": packet,
            "action_digest": checked.action_digest,
            "policy_digest": checked.policy_digest,
        }
    ), checked.expected


@dataclass(frozen=True)
class BoundaryRegression(JsonRecord):
    SCHEMA = "assurance_boundary_regression"
    NESTED = {"counterexample": CounterexampleRecord}
    case_id: str
    counterexample: CounterexampleRecord
    source_revision: str
    reproducer_digest: str
    benign_input: str
    benign_digest: str
    benign_expected: str
    review_digest: str | None = None
    reviewer_source_digest: str | None = None
    profile_digest: str | None = None
    provenance_kind: str = "closed_fixture_regression"
    advisory_only: bool = True
    host_boundary_exercised: bool = False

    def __post_init__(self):
        super().__post_init__()
        if self.source_revision != self.counterexample.revision or self.benign_digest != digest(
            "boundary_benign_input", self.benign_input
        ):
            raise ValueError("boundary regression source/benign binding differs")
        reviews = (self.review_digest, self.reviewer_source_digest, self.profile_digest)
        if any(v is None for v in reviews) != all(v is None for v in reviews):
            raise ValueError("partial regression review binding")

    @property
    def reviewed(self):
        # Inspection label only: serialized review hashes issue no approval.
        return self.review_digest is not None


def replay_boundary_regression(case, *, expected_revision):
    if not isinstance(case, BoundaryRegression) or case.source_revision != expected_revision:
        raise ValueError("boundary regression requires its exact pinned revision")
    if case.reproducer_digest != _reproducer_digest(case.counterexample.generator_version):
        raise ValueError("boundary regression reproducer changed; review a new case")
    failed = replay_counterexample(case.counterexample, expected_revision=expected_revision)
    if failed != "verified_failure":
        return failed
    control, expected = _benign_capture(case.counterexample)
    if control != case.benign_input or expected != case.benign_expected:
        raise ValueError("boundary regression benign counterpart changed")
    return "verified_failure_with_benign_control"


def prepare_boundary_regression(record, *, case_id, expected_revision):
    if (
        not isinstance(record, CounterexampleRecord)
        or replay_counterexample(record, expected_revision=expected_revision) != "verified_failure"
    ):
        raise ValueError("promotion requires a concretely reproduced counterexample")
    benign, expected = _benign_capture(record)
    case = BoundaryRegression(
        case_id,
        record,
        expected_revision,
        _reproducer_digest(record.generator_version),
        benign,
        digest("boundary_benign_input", benign),
        expected,
    )
    if (
        replay_boundary_regression(case, expected_revision=expected_revision)
        != "verified_failure_with_benign_control"
    ):
        raise ValueError("boundary regression failed independent replay")
    return case


@dataclass(frozen=True)
class ProtectedRegressionDestination:
    """Host-selected directory and virtual mapping, never caller JSON.

    The host must enforce the selected filesystem boundary/ACL and map the
    virtual protected path to this actual directory. SDK checks do not install
    a kernel sandbox or supply an in-process security boundary.
    """

    root: Path
    protected_runtime_path: str
    repository: RepositoryScope
    agent_boundary: RuntimeCapabilityBoundary
    runtime_source: RuntimeEvidenceSource

    def __post_init__(self):
        if (
            not isinstance(self.repository, RepositoryScope)
            or not isinstance(self.agent_boundary, RuntimeCapabilityBoundary)
            or not isinstance(self.runtime_source, RuntimeEvidenceSource)
        ):
            raise ValueError("regression destination requires protected host selections")
        path = self.protected_runtime_path
        if not _safe_path(path) or posixpath.normpath(path) != path or path == "/":
            raise ValueError("regression protected path is unsupported")
        boundary = self.agent_boundary
        if (
            not boundary.runtime_filesystem_guarantees
            or boundary.filesystem_semantics not in {"exact", "lexical_prefix"}
            or boundary.privilege.escalation is not False
            or boundary.privilege.required_euid == 0
        ):
            raise ValueError("regression corpus protection is unverified")
        for cap in boundary.filesystem:
            if (
                cap.path is None
                or not _safe_path(cap.path)
                or posixpath.normpath(cap.path) != cap.path
                or cap.access not in {"read", "metadata", "write", "delete", "execute"}
                or cap.scope not in {"exact", "prefix"}
            ):
                raise ValueError("regression corpus protection is unsupported")
            if cap.access in {"write", "delete"} and (
                cap.path == path
                or cap.path.startswith(path.rstrip("/") + "/")
                or path.startswith(cap.path.rstrip("/") + "/")
            ):
                raise ValueError("regression corpus or ancestor is agent-writable")
        with self.pin():
            pass

    @contextmanager
    def pin(self):
        with _directory(self.root) as (directory, parent):
            info = os.fstat(directory) if isinstance(directory, int) else parent.stat()
            if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
                raise ValueError("regression directory must be protected and operator owned")
            material = {
                "path_digest": core_digest(str(parent)),
                "identity": list(_identity(info)),
                "repository": self.repository.as_dict(),
                "boundary": self.agent_boundary.digest,
                "runtime": self.runtime_source.key,
                "protected_path": self.protected_runtime_path,
            }
            yield directory, parent, digest("regression_destination", material)


def regression_promotion_action(case, destination, source):
    if (
        not isinstance(case, BoundaryRegression)
        or not isinstance(destination, ProtectedRegressionDestination)
        or not isinstance(source, HostEvidenceSource)
    ):
        raise ValueError("promotion requires typed case/destination/host selections")
    if (
        case.reviewed
        or case.source_revision != source.repository.revision
        or source.repository != destination.repository
        or source.runtime_policy_digest != destination.runtime_source.policy_digest
    ):
        raise ValueError("promotion selection/revision/current policy mismatch")
    with destination.pin() as (_, _, destination_digest):
        return ActionEnvelope(
            "assurance",
            "promote_boundary_regression",
            {
                "case_digest": case.digest,
                "destination_digest": destination_digest,
                "filename": hashlib.sha256(case.case_id.encode()).hexdigest() + ".json",
                "source_key": source.key,
                "source_revision": case.source_revision,
                "authority_effect": "none",
                "scope": "closed_fixture_regression",
            },
        )


def promote_reviewed_boundary_regression(case, destination, source, profile, approval):
    """Write one new reviewed case; no overwrite/append, policy or source patch."""
    action = regression_promotion_action(case, destination, source)
    source._check_profile(profile)
    if not isinstance(approval, HostApproval) or (
        approval.source_key != source.key
        or approval.profile_digest != profile.digest
        or approval.action_digest != core_digest(action.as_dict())
    ):
        raise ValueError("promotion requires exact protected host review approval")
    if (
        replay_boundary_regression(case, expected_revision=source.repository.revision)
        != "verified_failure_with_benign_control"
    ):
        raise ValueError("reviewed counterexample no longer reproduces")
    reviewed = replace(
        case,
        review_digest=approval.digest,
        reviewer_source_digest=source.key,
        profile_digest=profile.digest,
    )
    raw = (canonical_json(reviewed.as_dict()) + "\n").encode()
    if len(raw) > MAX_CASE_BYTES:
        raise ValueError("regression case byte budget exceeded")
    with (
        destination.pin() as (directory, parent, destination_digest),
        _promotion_lock(directory, parent),
    ):
        if destination_digest != action.parameters["destination_digest"]:
            raise ValueError("regression destination changed during review")
        entries = directory_entries(destination.root, maximum=MAX_CASES + 1)
        if len(entries) - 1 >= MAX_CASES:
            raise ValueError("regression corpus case budget exceeded")
        filename = action.parameters["filename"]
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = (
            os.open(filename, flags, 0o600, dir_fd=directory)
            if isinstance(directory, int)
            else os.open(parent / filename, flags, 0o600)
        )
        # A failed/crashed write stays a partial file, never a successful receipt.
        # Loaders reject malformed/unreviewed bytes; no unrelated file is removed.
        with os.fdopen(descriptor, "wb") as output:
            _safe_stat(os.fstat(output.fileno()), directory=False)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if (
            read_scoped_file(destination.root, filename, maximum=MAX_CASE_BYTES, private=True)
            != raw
        ):
            raise ValueError("regression case changed during publication")
        if isinstance(directory, int):
            os.fsync(directory)
    return reviewed


@contextmanager
def _promotion_lock(directory, parent):
    # Cooperating writers serialize the count/create operation. A crashed lease
    # remains visible and is never stolen or treated as a complete corpus.
    name = ".ordin-boundary-lock"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = (
        os.open(name, flags, 0o600, dir_fd=directory)
        if isinstance(directory, int)
        else os.open(parent / name, flags, 0o600)
    )
    try:
        _safe_stat(os.fstat(descriptor), directory=False)
        yield
    finally:
        os.close(descriptor)
        if isinstance(directory, int):
            os.unlink(name, dir_fd=directory)
        else:
            (parent / name).unlink()


def load_boundary_regressions(destination):
    if not isinstance(destination, ProtectedRegressionDestination):
        raise ValueError("corpus requires a protected selected destination")
    result = []
    ids = set()
    with destination.pin():
        for entry in directory_entries(destination.root, maximum=MAX_CASES):
            if entry.kind != "file" or not re.fullmatch(r"[a-f0-9]{64}\.json", entry.name):
                raise ValueError("regression corpus contains an unsupported entry")
            case = BoundaryRegression.from_json(
                read_scoped_file(destination.root, entry.name, maximum=MAX_CASE_BYTES, private=True)
            )
            if (
                not case.reviewed
                or case.source_revision != destination.repository.revision
                or case.case_id in ids
                or entry.name != hashlib.sha256(case.case_id.encode()).hexdigest() + ".json"
            ):
                raise ValueError("corpus case review/revision/identity differs")
            ids.add(case.case_id)
            result.append(case)
    return tuple(result)


def replay_boundary_regression_corpus(destination, *, expected_cases):
    """Explicit mandatory manifest prevents missing/corrupted cases from passing."""
    if not isinstance(expected_cases, dict) or not 1 <= len(expected_cases) <= MAX_CASES:
        raise ValueError("regression replay requires a bounded nonempty mandatory manifest")
    expected_cases = dict(freeze(expected_cases))
    for case_id, pin in expected_cases.items():
        validate("assurance_authority_ref", {"authority_id": case_id, "boundary_digest": pin})
    cases = load_boundary_regressions(destination)
    if {case.case_id for case in cases} != set(expected_cases):
        raise ValueError("regression corpus mandatory case inventory differs")
    for case in cases:
        if case.digest != expected_cases[case.case_id]:
            raise ValueError("regression corpus differs from the reviewed mandatory manifest")
    outcomes = []
    for case in cases:
        result = replay_boundary_regression(case, expected_revision=destination.repository.revision)
        outcomes.append({"case_id": case.case_id, "case_digest": case.digest, "result": result})
    return {
        "schema_version": "ordin.assurance_boundary_regression_replay.v1",
        "source_revision": destination.repository.revision,
        "manifest_digest": digest("boundary_regression_manifest", expected_cases),
        "cases": outcomes,
        "all_reproduced": all(
            v["result"] == "verified_failure_with_benign_control" for v in outcomes
        ),
        "provenance_kind": "closed_fixture_regression",
        "advisory_only": True,
        "host_boundary_exercised": False,
    }
