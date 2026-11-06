"""Tenant-keyed redaction, anchored chains and honest bounded retention."""

from copy import deepcopy
import json
import sqlite3

import pytest

from ordin.swarm.audit import (
    SwarmAuditJournal,
    SwarmAuditPolicy,
    TenantRedactor,
    verify_swarm_audit,
)


def journal(tmp_path, *, policy=None):
    now, operator = [100.0], object()
    selected = SwarmAuditJournal(
        tmp_path / "audit.db",
        key=b"K" * 32,
        tenant_id="tenant",
        operator=operator,
        policy=policy or SwarmAuditPolicy(),
        clock=lambda: now[0],
        create=True,
    )
    return selected, operator, now


def append(selected, operator, action="action"):
    return selected._append(
        kind="decision",
        state="reviewed",
        evidence="intent",
        refs={"action": action, "resource": "https://private.invalid/?token=SYNTHETIC_SECRET"},
        facts={"disposition": "escalate", "risk": "high"},
        operator=operator,
    )


def test_hmac_redaction_is_tenant_domain_scoped_and_not_dictionary_sha(tmp_path):
    selected, operator, _ = journal(tmp_path)
    event = append(selected, operator)
    first = TenantRedactor(b"K" * 32, "tenant")
    second = TenantRedactor(b"K" * 32, "other")
    assert first.ref("resource", "common/path") != second.ref("resource", "common/path")
    assert first.ref("resource", "value") != first.ref("action", "value")
    raw = json.dumps(selected.export(operator=operator))
    assert "private.invalid" not in raw and "SYNTHETIC_SECRET" not in raw
    assert "token=" not in raw and event["refs"]["resource"].startswith("hmac:")
    assert b"SYNTHETIC_SECRET" not in selected.path.read_bytes()


def test_reordering_body_edit_and_anchored_truncation_are_detected(tmp_path):
    selected, operator, _ = journal(tmp_path)
    append(selected, operator, "first")
    append(selected, operator, "second")
    checkpoint = selected.checkpoint(operator=operator)
    bundle = selected.export(operator=operator)
    assert verify_swarm_audit(bundle, checkpoint).valid
    edited = deepcopy(bundle)
    edited["events"].reverse()
    assert not verify_swarm_audit(edited).valid
    edited = deepcopy(bundle)
    edited["events"][0]["facts"]["disposition"] = "execute"
    assert not verify_swarm_audit(edited).valid
    edited = deepcopy(bundle)
    edited["events"].pop()
    edited["tail_sequence"], edited["tail_hash"] = 1, edited["events"][0]["event_hash"]
    assert verify_swarm_audit(edited).valid
    assert not verify_swarm_audit(edited, checkpoint).valid


def test_explicit_reopen_never_reinitializes_corrupt_or_wrong_key_history(tmp_path):
    selected, operator, _ = journal(tmp_path)
    append(selected, operator)
    with pytest.raises((ValueError, OSError)):
        SwarmAuditJournal(selected.path, key=b"Z" * 32, tenant_id="tenant", operator=object())
    with pytest.raises((ValueError, OSError)):
        SwarmAuditJournal(selected.path, key=b"K" * 32, tenant_id="other", operator=object())
    with sqlite3.connect(selected.path) as connection:
        connection.execute("DELETE FROM audit_events")
    with pytest.raises(ValueError):
        selected.export(operator=operator)
    with pytest.raises(FileExistsError):
        SwarmAuditJournal(
            selected.path, key=b"K" * 32, tenant_id="tenant", operator=operator, create=True
        )


def test_retention_is_bounded_with_continuous_tail_and_explicit_prefix_gap(tmp_path):
    selected, operator, now = journal(tmp_path, policy=SwarmAuditPolicy(2, 5, 4))
    first = append(selected, operator, "first")
    checkpoint = selected.checkpoint(operator=operator)
    append(selected, operator, "second")
    append(selected, operator, "third")
    bundle = selected.export(operator=operator)
    assert len(bundle["events"]) == 2 and bundle["first_sequence"] == 2
    assert bundle["base_hash"] == first["event_hash"]
    result = verify_swarm_audit(bundle, checkpoint)
    assert result.valid and "audit.retained_prefix_unavailable" in result.proof_gaps
    now[0] += 6
    expired = selected.export(operator=operator)
    assert expired["events"] == [] and expired["tail_sequence"] == 3
    assert not verify_swarm_audit(expired, checkpoint).valid


def test_model_risk_cannot_claim_observed_effects_or_insert_raw_fact_fields(tmp_path):
    selected, operator, _ = journal(tmp_path)
    for facts, evidence in (
        ({"prompt": "secret"}, "diagnostic"),
        ({"model_risk": "high"}, "observed"),
    ):
        with pytest.raises(ValueError):
            selected._append(
                kind="risk_signal",
                state="risk_reported",
                evidence=evidence,
                refs={},
                facts=facts,
                operator=operator,
            )
    with pytest.raises(ValueError):
        append(selected, object())
    assert selected.export(operator=operator)["events"] == []


def test_backwards_clock_and_sql_index_tampering_fail_closed(tmp_path):
    selected, operator, now = journal(tmp_path)
    append(selected, operator)
    now[0] = 99
    with pytest.raises(ValueError):
        selected.export(operator=operator)
    now[0] = 100
    with sqlite3.connect(selected.path) as connection:
        connection.execute("UPDATE audit_events SET admitted_at=101")
    with pytest.raises(ValueError):
        selected.export(operator=operator)
