"""Data examples for optional contracts; core tests import no provider package."""


def semantic_contract_samples():
    policy = {
        "schema_version": "ordin.assurance_semantic_policy.v1",
        "mode": "disabled",
        "enabled_question_ids": ["material_intent_mismatch"],
        "mandatory_action_kinds": [],
        "mandatory_effects": [],
        "required_question_ids": [],
        "escalation_threshold": 0.8,
        "uncertainty_margin": 0.1,
        "deadline_ms": 250,
        "max_total_calls": 32,
        "max_concurrency": 2,
        "max_input_bytes": 12288,
    }
    state = {
        "schema_version": "ordin.assurance_semantic_state.v1",
        "action_digest": "a" * 64,
        "baseline_evidence_digest": "b" * 64,
        "gate_configuration_digest": "c" * 64,
        "host_context_digest": None,
        "task_context_digest": None,
        "host_source_key": None,
        "action_kind": "shell",
        "risk": "unknown",
        "effects": [],
        "authorized_task": None,
        "snippets": [],
        "signals": [],
        "remote_eligible": False,
        "omitted_fields": 1,
        "redaction_policy_id": "ordin.semantic_privacy.v1",
    }
    questions = {
        "schema_version": "ordin.assurance_security_questions.v1",
        "question_set_id": "ordin.security_questions.v1",
        "question_ids": ["material_intent_mismatch"],
        "interpretation": "Probability of yes/true; predictions, not security proof or authorization.",
    }
    decision = {
        "schema_version": "ordin.assurance_semantic_decision.v1",
        "decision_id": "fixture-semantic",
        "mode": "disabled",
        "disposition": "execute",
        "baseline_disposition": "execute",
        "baseline_evidence_digest": "b" * 64,
        "router_configuration_digest": "d" * 64,
        "state_digest": None,
        "question_set_digest": None,
        "model_evidence": None,
        "model_invoked": False,
        "mandatory": False,
        "uncertain_question_ids": [],
        "reason_codes": ["semantic.disabled"],
        "elapsed_ms": 0,
        "advisory_only": True,
    }
    return {
        "assurance_semantic_inspection": {
            "schema_version": "ordin.assurance_semantic_inspection.v1",
            "source_key": "c" * 64,
            "action_digest": "a" * 64,
            "reasons": ["ambiguous_task_alignment"],
        },
        "assurance_semantic_policy": policy,
        "assurance_semantic_state": state,
        "assurance_security_questions": questions,
        "assurance_semantic_decision": decision,
    }
