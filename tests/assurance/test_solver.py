"""Real finite SMT results must survive independent concrete authority replay."""

import builtins
from dataclasses import replace
import json

import pytest

from ordin.assurance.solver import (
    SolverChallenge,
    challenge_capability_intersection,
    replay_solver_candidate,
)


def test_missing_solver_remains_inconclusive_and_default_import_is_local(monkeypatch):
    original = builtins.__import__

    def absent(name, *args, **kwargs):
        if name == "z3":
            raise ImportError("optional solver not selected")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", absent)
    result = challenge_capability_intersection(revision="fixture-v1")
    assert result.solver_result == "unavailable" and result.conclusion == "inconclusive"
    assert result.solver_version is None and result.initial_mask is None
    assert result.benign_control_result == "within_boundary"
    assert SolverChallenge.from_dict(result.as_dict()) == result
    with pytest.raises(ValueError, match="conclusion"):
        replace(result, conclusion="no_counterexample_in_finite_model")


def test_solver_abstraction_candidate_is_not_a_confirmed_failure(monkeypatch):
    pytest.importorskip("z3")

    def forbidden(*args, **kwargs):
        pytest.fail("finite SMT challenge attempted network/process execution")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    result = challenge_capability_intersection(
        revision="fixture-v1", encoding="seeded_union_abstraction"
    )
    assert result.solver_result == "sat" and result.solver_version
    assert result.initial_mask & 1 != result.initial_mask
    assert result.minimized_mask in {2, 4}
    assert result.initial_replay_result == result.concrete_replay_result == "exceeds_boundary"
    assert result.benign_control_result == "within_boundary"
    assert result.conclusion == "candidate_not_reproduced"
    assert not result.host_boundary_exercised and result.origin == "solver_hypothesis"
    assert SolverChallenge.from_dict(result.as_dict()) == result
    assert (
        replay_solver_candidate(result, expected_revision="fixture-v1")
        == "candidate_not_reproduced"
    )
    for changes in (
        {"conclusion": "verified_finite_failure"},
        {"concrete_replay_result": "within_boundary", "conclusion": "verified_finite_failure"},
        {"minimized_mask": 1},
        {
            "solver_result": "unsat",
            "initial_mask": None,
            "minimized_mask": None,
            "initial_replay_result": None,
            "concrete_replay_result": None,
            "conclusion": "no_counterexample_in_finite_model",
        },
        {"solver_input_parts": ("(assert true)",)},
        {"proof_gaps": ()},
        {"host_boundary_exercised": True},
    ):
        with pytest.raises(ValueError):
            replace(result, **changes)
    with pytest.raises(ValueError, match="exact pinned revision"):
        replay_solver_candidate(result, expected_revision="fixture-v2")


def test_exact_intersection_solver_and_concrete_verifier_agree():
    pytest.importorskip("z3")
    result = challenge_capability_intersection(revision="fixture-v1")
    assert result.solver_result == "unsat"
    assert result.conclusion == "no_counterexample_in_finite_model"
    assert result.initial_mask is result.minimized_mask is result.concrete_replay_result is None
    assert result.proof_gaps and not result.host_boundary_exercised


def test_finite_encoding_matches_every_concrete_exact_rights_combination():
    from itertools import product
    from ordin.assurance.solver import _replay

    # Exhaust the declared three-bit domain against the production verifier.
    # The arithmetic oracle is independent of its domain-containment algorithm.
    for parent, operator, task in product(range(8), repeat=3):
        intersection = parent & operator & task
        for request in range(8):
            expected = (
                "within_boundary" if request & intersection == request else "exceeds_boundary"
            )
            assert _replay(request, parent, operator, task) == expected


def test_solver_unknown_is_never_a_finite_pass(monkeypatch):
    z3 = pytest.importorskip("z3")
    solver_type = z3.Solver

    class UnknownSolver:
        def __init__(self, **kwargs):
            self.solver = solver_type(**kwargs)

        def set(self, **kwargs):
            self.solver.set(**kwargs)

        def from_string(self, source):
            self.solver.from_string(source)

        def check(self):
            return z3.unknown

    monkeypatch.setattr(z3, "Solver", UnknownSolver)
    result = challenge_capability_intersection(revision="fixture-v1")
    assert result.solver_result == "unknown" and result.conclusion == "inconclusive"
    assert result.initial_mask is None


@pytest.mark.parametrize(
    "changes",
    [
        {"parent_mask": True},
        {"operator_mask": 8},
        {"task_mask": -1},
        {"encoding": []},
        {"encoding": "untrusted_smt_file"},
        {"timeout_ms": 0},
        {"timeout_ms": 10001},
        {"seed": True},
        {"revision": ""},
    ],
)
def test_hostile_or_unbounded_solver_inputs_are_refused(changes):
    with pytest.raises(ValueError):
        challenge_capability_intersection(**{"revision": "fixture-v1", **changes})


def test_solver_cli_candidate_and_revision_bound_replay(tmp_path, capsys):
    pytest.importorskip("z3")
    from ordin.assurance.cli import main

    path = tmp_path / "solver.json"
    assert (
        main(
            [
                "challenge",
                "solve",
                "--revision",
                "fixture-v1",
                "--encoding",
                "seeded_union_abstraction",
                "--report",
                str(path),
            ]
        )
        == 2
    )
    result = json.loads(capsys.readouterr().out)
    assert result["conclusion"] == "candidate_not_reproduced"
    assert main(["challenge", "solver-replay", str(path), "--revision", "fixture-v1"]) == 2
    assert json.loads(capsys.readouterr().out)["conclusion"] == "candidate_not_reproduced"
    assert main(["challenge", "solver-replay", str(path), "--revision", "fixture-v2"]) == 2
    assert json.loads(capsys.readouterr().err)["coverage"] == "unknown"
