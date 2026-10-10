"""Explicit installed worker only: local verified files, typed JSON, no tools."""

from __future__ import annotations

import contextlib
import importlib.metadata
import json
import math
import os
import sys


def _read(limit):
    from ordin.assurance.codex_security._validation import loads

    raw = sys.stdin.buffer.readline(limit + 1)
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise ValueError("worker input exceeds protocol budget")
    return loads(raw)


def _emit(packet):
    raw = json.dumps(packet, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(raw) > 65536:
        raise ValueError("worker output exceeds protocol budget")
    sys.stdout.write(raw + "\n")
    sys.stdout.flush()


def main() -> int:
    # All downstream ML imports happen only in this explicitly launched worker.
    for key in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY"):
        if os.environ.get(key) != "1":
            return 2
    from ordin_decision_models.checkpoints import LocalCheckpoint
    from ordin_decision_models.protocol import SecurityQuestionSet
    from ordin.assurance._json import digest, validate

    initial = _read(16384)
    if set(initial) != {"operation", "checkpoint"} or initial["operation"] != "load":
        return 2
    checkpoint = LocalCheckpoint.from_worker_dict(initial["checkpoint"])
    checkpoint.verify()
    if importlib.metadata.version("laya") != "0.4.1":
        _emit({"status": "version_mismatch"})
        return 2
    with contextlib.redirect_stdout(sys.stderr):
        import laya

    if laya.__version__ != "0.4.1":
        _emit({"status": "version_mismatch"})
        return 2
    with contextlib.redirect_stdout(sys.stderr):
        agent = laya.load(
            str(checkpoint.root),
            device=checkpoint.device,
            expected_sha256=dict(checkpoint.files),
            fast=False,
            compile=False,
            backend="eager",
        )
    if str(agent.device) != checkpoint.device:
        _emit({"status": "device_mismatch"})
        return 2
    checkpoint.verify()  # Refuse loader mutation even after the preflight.
    _emit(
        {
            "status": "ready",
            "package_version": "0.4.1",
            "manifest_digest": checkpoint.manifest_digest,
            "device": str(agent.device),
            "max_tokens": checkpoint.max_tokens,
        }
    )
    for _ in range(32):
        request = _read(16384)
        if (
            set(request)
            != {
                "operation",
                "request_id",
                "state",
                "question_set",
                "state_digest",
                "question_set_digest",
            }
            or request["operation"] != "evaluate"
        ):
            return 2
        validate("assurance_semantic_state", request["state"])
        if digest("assurance_semantic_state", request["state"]) != request["state_digest"]:
            return 2
        questions = SecurityQuestionSet.from_dict(request["question_set"])
        if questions.digest != request["question_set_digest"]:
            return 2
        state = request["state"]
        model_input = {
            "context_version": "ordin.semantic_context.v1",
            "authorized_task": state["authorized_task"],
            "action_kind": state["action_kind"],
            "risk": state["risk"],
            "effects": state["effects"],
            "snippets": [
                {key: snippet[key] for key in ("text", "origin_kind", "classification")}
                for snippet in state["snippets"]
            ],
            "signals": state["signals"],
        }
        with contextlib.redirect_stdout(sys.stderr):
            result = agent.predict(
                model_input, questions.provider_questions(), max_len=checkpoint.max_tokens
            )
        usage = result.get("usage") if isinstance(result, dict) else None
        if (
            not isinstance(usage, dict)
            or usage.get("truncated") is not False
            or usage.get("state_tokens_dropped", 0) != 0
            or usage.get("truncated_questions")
            or usage.get("options")
        ):
            _emit({"status": "incomplete", "request_id": request["request_id"]})
            continue
        returned = result.get("answers")
        if not isinstance(returned, dict) or set(returned) != set(questions.question_ids):
            _emit({"status": "malformed", "request_id": request["request_id"]})
            continue
        answers = {}
        for identifier in questions.question_ids:
            value = returned[identifier]
            if (
                not isinstance(value, dict)
                or value.get("type") != "noul"
                or type(value.get("noul")) not in {float, int}
                or not math.isfinite(value["noul"])
                or not 0 <= value["noul"] <= 1
            ):
                raise ValueError("local typed answer malformed")
            answers[identifier] = float(value["noul"])
        _emit(
            {
                "status": "completed",
                "request_id": request["request_id"],
                "state_digest": request["state_digest"],
                "question_set_digest": questions.digest,
                "manifest_digest": checkpoint.manifest_digest,
                "answers": answers,
                "input_tokens": usage.get("input_tokens"),
            }
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Vendor exceptions can contain source/paths. Routine stdout is coarse.
        _emit({"status": "error"})
        raise SystemExit(2) from None
