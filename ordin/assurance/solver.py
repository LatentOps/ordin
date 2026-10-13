"""Optional finite SMT candidates with independent concrete delegation replay.

Z3 is imported only by explicit challenge calls. No solver artifact or SAT result
is authority, a host observation, or a confirmed production vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability

from .delegation import DelegationAuthority, verify_delegation_subset
from ._json import validate
from .models import JsonRecord

VERSION = "capability-intersection-smt-v1"
RIGHTS = ("read", "write", "delete")
ASSUMPTIONS = (
    "Three independent atomic filesystem rights: bit 0 read, bit 1 write, bit 2 delete.",
    "Every capability names the same exact synthetic path; no lexical prefix, alias or symlink abstraction.",
    "Parent, operator and task maxima must all contain the requested rights.",
    "Other capability/request domains are empty; approval flags are false.",
    "The union variant deliberately weakens only the solver abstraction, never the concrete verifier.",
)
GAPS = (
    "Only exact synthetic declaration containment is exercised; no physical host enforcement.",
    "UNSAT covers this three-bit model only; SAT remains a candidate until independent concrete replay.",
)


def _input(parent: int, operator: int, task: int, encoding: str) -> str:
    intersection = parent & operator & task
    maximum = intersection if encoding == "exact_intersection" else parent | operator | task
    return (
        "\n".join(
            (
                "(set-logic QF_BV)",
                "(declare-fun request () (_ BitVec 3))",
                "(assert (not (= request #b000)))",
                f"(assert (= (bvand request (bvnot #b{maximum:03b})) #b000))",
                f"(assert (not (= (bvand request (bvnot #b{intersection:03b})) #b000)))",
                "(check-sat)",
            )
        )
        + "\n"
    )


def _authority(mask: int, name: str) -> DelegationAuthority:
    return DelegationAuthority(
        RuntimeCapabilityBoundary(
            name,
            filesystem=tuple(
                FilesystemCapability(right, "/synthetic/resource", "exact")
                for index, right in enumerate(RIGHTS)
                if mask & (1 << index)
            ),
        )
    )


def _replay(mask: int, parent: int, operator: int, task: int) -> str:
    return verify_delegation_subset(
        _authority(mask, "candidate"),
        _authority(parent, "parent"),
        _authority(operator, "operator"),
        _authority(task, "task"),
    ).result


def _abstract_failure(mask: int, parent: int, operator: int, task: int, encoding: str) -> bool:
    intersection = parent & operator & task
    maximum = intersection if encoding == "exact_intersection" else parent | operator | task
    return bool(mask and mask & maximum == mask and mask & intersection != mask)


def _minimize(mask: int, parent: int, operator: int, task: int, encoding: str) -> int:
    # At most seven candidates; retain the identical property/maxima/encoding
    # and only remove requested rights from the original SAT assignment.
    return next(
        value
        for value in range(1, 8)
        if value & mask == value and _abstract_failure(value, parent, operator, task, encoding)
    )


@dataclass(frozen=True)
class SolverChallenge(JsonRecord):
    SCHEMA = "assurance_solver_challenge"
    revision: str
    encoding: str
    parent_mask: int
    operator_mask: int
    task_mask: int
    seed: int
    timeout_ms: int
    solver_version: str | None
    solver_result: str
    solver_input_parts: tuple[str, ...]
    solver_input_sha256: str
    initial_mask: int | None
    minimized_mask: int | None
    initial_replay_result: str | None
    concrete_replay_result: str | None
    benign_control_result: str
    conclusion: str
    generator_version: str = VERSION
    assumptions: tuple[str, ...] = ASSUMPTIONS
    proof_gaps: tuple[str, ...] = GAPS
    host_boundary_exercised: bool = False
    origin: str = "solver_hypothesis"

    def __post_init__(self):
        super().__post_init__()
        expected_input = _input(self.parent_mask, self.operator_mask, self.task_mask, self.encoding)
        if (
            self.solver_input_parts != tuple(expected_input.splitlines())
            or self.solver_input_sha256 != hashlib.sha256(expected_input.encode()).hexdigest()
            or self.assumptions != ASSUMPTIONS
            or self.proof_gaps != GAPS
            or (self.solver_result == "unavailable") != (self.solver_version is None)
        ):
            raise ValueError("solver input, version or finite assumptions differ")
        maxima = self.parent_mask, self.operator_mask, self.task_mask
        control = _replay(self.parent_mask & self.operator_mask & self.task_mask, *maxima)
        if self.benign_control_result != control:
            raise ValueError("solver benign control differs from concrete replay")
        if self.solver_result == "sat":
            if (
                self.initial_mask is None
                or self.minimized_mask is None
                or not _abstract_failure(self.initial_mask, *maxima, self.encoding)
                or self.minimized_mask != _minimize(self.initial_mask, *maxima, self.encoding)
                or self.initial_replay_result != _replay(self.initial_mask, *maxima)
                or self.concrete_replay_result != _replay(self.minimized_mask, *maxima)
            ):
                raise ValueError("solver assignment/shrink differs from actual concrete replay")
            conclusion = (
                "verified_finite_failure"
                if self.initial_replay_result == self.concrete_replay_result == "within_boundary"
                else "candidate_not_reproduced"
                if self.initial_replay_result == self.concrete_replay_result == "exceeds_boundary"
                else "inconclusive"
            )
        else:
            if any(
                value is not None
                for value in (
                    self.initial_mask,
                    self.minimized_mask,
                    self.initial_replay_result,
                    self.concrete_replay_result,
                )
            ):
                raise ValueError("solver without SAT cannot claim a concretely replayed assignment")
            conclusion = (
                "no_counterexample_in_finite_model"
                if self.solver_result == "unsat"
                else "inconclusive"
            )
            # There are just seven nonempty assignments. Do not trust an
            # imported UNSAT label when the exact captured formula admits one.
            if self.solver_result == "unsat" and any(
                _abstract_failure(value, *maxima, self.encoding) for value in range(1, 8)
            ):
                raise ValueError("solver UNSAT claim contradicts its finite input")
        if self.conclusion != conclusion:
            raise ValueError("solver conclusion differs from concrete reproduction")


def challenge_capability_intersection(
    *,
    revision: str,
    parent_mask: int = 1,
    operator_mask: int = 3,
    task_mask: int = 5,
    encoding: str = "exact_intersection",
    seed: int = 14,
    timeout_ms: int = 1000,
) -> SolverChallenge:
    """Solve a bounded, closed formula; replay/shrink SAT rights in the real verifier.

    No caller-supplied SMT/code is parsed. Missing Z3 and solver unknown/timeout
    return inconclusive artifacts. A seeded union abstraction is a harness
    control and cannot change the actual delegation verifier.
    """
    if (
        any(
            type(value) is not int or not 0 <= value <= 7
            for value in (parent_mask, operator_mask, task_mask)
        )
        or not isinstance(encoding, str)
        or encoding not in {"exact_intersection", "seeded_union_abstraction"}
        or type(seed) is not int
        or not 0 <= seed < 2**31
        or type(timeout_ms) is not int
        or not 1 <= timeout_ms <= 10000
    ):
        raise ValueError("unsupported finite solver configuration")
    validate("assurance_authority_ref", {"authority_id": revision, "boundary_digest": "0" * 64})
    source = _input(parent_mask, operator_mask, task_mask, encoding)
    result, version, initial = "unavailable", None, None
    try:
        import z3
    except (ImportError, OSError):
        pass
    else:
        version = z3.get_version_string()
        context = z3.Context()
        solver = z3.Solver(ctx=context)
        solver.set(timeout=timeout_ms, rlimit=100000, random_seed=seed)
        try:
            solver.from_string(source)
            checked = solver.check()
            result = "sat" if checked == z3.sat else "unsat" if checked == z3.unsat else "unknown"
            if result == "sat":
                initial = (
                    solver.model()
                    .eval(z3.BitVec("request", 3, ctx=context), model_completion=True)
                    .as_long()
                )
        except z3.Z3Exception:
            result, initial = "unknown", None
    maxima = parent_mask, operator_mask, task_mask
    minimized = _minimize(initial, *maxima, encoding) if initial is not None else None
    before = _replay(initial, *maxima) if initial is not None else None
    after = _replay(minimized, *maxima) if minimized is not None else None
    conclusion = (
        "verified_finite_failure"
        if before == after == "within_boundary"
        else "candidate_not_reproduced"
        if before == after == "exceeds_boundary"
        else "no_counterexample_in_finite_model"
        if result == "unsat"
        else "inconclusive"
    )
    return SolverChallenge(
        revision,
        encoding,
        *maxima,
        seed,
        timeout_ms,
        version,
        result,
        tuple(source.splitlines()),
        hashlib.sha256(source.encode()).hexdigest(),
        initial,
        minimized,
        before,
        after,
        _replay(parent_mask & operator_mask & task_mask, *maxima),
        conclusion,
    )


def replay_solver_candidate(record: SolverChallenge, *, expected_revision: str) -> str:
    """Reconstruct the closed formula and concrete rights; no solver is required."""
    if not isinstance(record, SolverChallenge) or record.revision != expected_revision:
        raise ValueError("solver replay requires the exact pinned revision")
    # Rebuild and revalidate rather than trust imported status or serialized SMT.
    return SolverChallenge.from_dict(record.as_dict()).conclusion
