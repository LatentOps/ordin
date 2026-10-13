"""Pinned finite synthetic programs and canonical lexical path test inputs."""

import hashlib
import re
from dataclasses import dataclass, field

from ._files import read_scoped_file
from ._json import digest, loads
from .inventory import AuthorizedRepository, verify_source_reference
from .models import JsonRecord, RepositoryScope, SourceReference, _unique
from .validation_models import _ValidationAuthority
from .validation import _issue
from ._sandbox_worker import vet_program, expected_path_result

PATH_PROPERTY_DIGEST = digest(
    "synthetic_path_property",
    {
        "version": "ordin.synthetic_path_boundary.v1",
        "inputs": "canonical absolute /synthetic paths",
        "expected": "path equals root or path has root followed by slash prefix",
        "physical_filesystem": False,
    },
)


@dataclass(frozen=True)
class SyntheticPathCase(JsonRecord):
    SCHEMA = "synthetic_path_case"
    case_id: str
    path: str
    root: str

    def __post_init__(self):
        super().__post_init__()
        for value in (self.path, self.root):
            if not re.fullmatch(r"/synthetic(?:/[a-z0-9_.-]{1,32})*", value) or any(
                segment in {".", ".."} for segment in value.split("/")
            ):
                raise ValueError(
                    "synthetic test paths must be canonical within the fixed namespace"
                )

    @property
    def expected(self):
        return expected_path_result(self.path, self.root)


@dataclass(frozen=True)
class SyntheticPathSuite(JsonRecord):
    SCHEMA = "assurance_synthetic_path_suite"
    MANY = {"cases": SyntheticPathCase}
    suite_id: str
    cases: tuple[SyntheticPathCase, ...]

    def __post_init__(self):
        super().__post_init__()
        _unique(self.cases, "case_id")
        if len({(case.path, case.root) for case in self.cases}) != len(self.cases):
            raise ValueError("duplicate synthetic test input")
        if (
            len(self.cases) < 2
            or not any(case.expected for case in self.cases)
            or not any(not case.expected for case in self.cases)
        ):
            raise ValueError("synthetic suite needs boundary violations and benign controls")


@dataclass(frozen=True)
class VettedProgram(JsonRecord):
    SCHEMA = "assurance_vetted_program"
    NESTED = {"repository": RepositoryScope, "source": SourceReference}
    repository: RepositoryScope
    source: SourceReference
    program_digest: str
    predicate: str = "synthetic_path_boundary"
    _program: str = field(default="", repr=False, compare=False)
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
            or hashlib.sha256(self._program.encode()).hexdigest() != self.program_digest
            or vet_program(self._program) != self._program
        ):
            raise ValueError("vetted program requires actual inspected grammar bytes")


@dataclass(frozen=True)
class SelectedSyntheticSuite:
    suite: SyntheticPathSuite
    source: SourceReference
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    @property
    def digest(self):
        return digest(
            "selected_synthetic_suite", {"suite": self.suite.digest, "source": self.source.digest}
        )

    def __post_init__(self):
        if (
            not isinstance(self.suite, SyntheticPathSuite)
            or not isinstance(self.source, SourceReference)
            or not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("synthetic suite requires an actual pinned source fixture")


def load_vetted_program(scope: AuthorizedRepository, reference: SourceReference):
    if not verify_source_reference(scope, reference):
        raise ValueError("synthetic program source is stale or invalid")
    raw = read_scoped_file(scope.root, reference.path, maximum=4096)
    if hashlib.sha256(raw).hexdigest() != reference.content_digest:
        raise ValueError("synthetic program changed during selection")
    code = vet_program(raw.decode("utf-8"))  # Comments/private source text never reach the broker.
    return _issue(
        VettedProgram,
        dict(
            repository=scope.repository,
            source=reference,
            program_digest=hashlib.sha256(code.encode()).hexdigest(),
            predicate="synthetic_path_boundary",
            _program=code,
        ),
    )


def load_synthetic_suite(scope: AuthorizedRepository, reference: SourceReference):
    if not verify_source_reference(scope, reference) or reference.symbol is not None:
        raise ValueError("synthetic test fixture source is stale or invalid")
    raw = read_scoped_file(scope.root, reference.path, maximum=65536)
    if hashlib.sha256(raw).hexdigest() != reference.content_digest:
        raise ValueError("synthetic test fixture changed during selection")
    suite = SyntheticPathSuite.from_dict(loads(raw))
    material = digest(
        "selected_synthetic_suite", {"suite": suite.digest, "source": reference.digest}
    )
    return SelectedSyntheticSuite(suite, reference, _ValidationAuthority(material))
