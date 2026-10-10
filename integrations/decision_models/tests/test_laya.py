"""Actual local worker lifecycle over trusted synthetic checkpoint/IPC fixtures."""

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time

import pytest

from ordin.assurance import (
    HostEvidenceSource,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityProfile,
    load_approved_profile,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability
from ordin.runtime_observation import RuntimeEvidenceSource
from ordin_decision_models import RoutingPolicy, SemanticInspectionRouter
from ordin_decision_models.checkpoints import LocalCheckpoint, _checkpoint_json
from ordin_decision_models.laya import (
    LayaDecisionModel,
    LocalModelRuntime,
    authorize_local_model,
    local_setup_action,
)

from test_routing import fixture


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checkpoint_at(root):
    root.mkdir()
    (root / "encoder").mkdir()
    (root / "tokenizer").mkdir()
    for name, packet in (
        ("rl_agent_config.json", {"encoder": "fixture", "max_len": 512}),
        ("encoder/config.json", {"model_type": "modernbert"}),
        ("tokenizer/tokenizer_config.json", {"tokenizer_class": "PreTrainedTokenizerFast"}),
        ("tokenizer/tokenizer.json", {"model": {"type": "BPE", "vocab": {"fixture": 0}}}),
    ):
        (root / name).write_text(json.dumps(packet), encoding="utf-8")
    (root / "model.safetensors").write_bytes(b"synthetic-weights-never-loaded")
    return LocalCheckpoint(
        root,
        "a" * 40,
        tuple(
            (name, sha(root / name))
            for name in (
                "rl_agent_config.json",
                "encoder/config.json",
                "tokenizer/tokenizer_config.json",
                "tokenizer/tokenizer.json",
                "model.safetensors",
            )
        ),
    )


def write_fake(worker, behavior="normal"):
    code = f"""import sys, json, hashlib, os, time
behavior = {behavior!r}
assert os.environ.get("HF_HUB_OFFLINE") == "1"
assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"
assert "OPENAI_API_KEY" not in os.environ
assert "AMBIENT_PRIVATE_TOKEN" not in os.environ
initial = json.loads(sys.stdin.readline())
cp = initial["checkpoint"]
material = {{"root_digest": hashlib.sha256(cp["root"].encode()).hexdigest(), "revision": cp["revision"],
            "files": sorted(cp["files"]), "device": cp["device"], "max_tokens": cp["max_tokens"], "max_total_bytes": cp["max_total_bytes"]}}
manifest = hashlib.sha256(("ordin.assurance:laya_checkpoint:v1\\0" + json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()
if behavior == "setup_timeout": time.sleep(60)
ready = {{"status":"ready","package_version":"0.4.1","manifest_digest":manifest,"device":cp["device"],"max_tokens":cp["max_tokens"]}}
if behavior == "bad_handshake": ready["package_version"] = "0.5.0"
print(json.dumps(ready),flush=True)
for line in sys.stdin:
    request = json.loads(line)
    if behavior == "eval_timeout": time.sleep(60)
    if behavior == "child_hang":
        import subprocess
        subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])
        time.sleep(60)
    if behavior == "overflow":
        print("x" * 100000,flush=True)
        continue
    if behavior == "stderr_overflow":
        sys.stderr.write("synthetic-private-text " * 10000)
        sys.stderr.flush()
        time.sleep(60)
    if behavior == "malformed":
        print("not-json",flush=True)
        continue
    if behavior == "truncated":
        print(json.dumps({{"status":"incomplete","request_id":request["request_id"]}}),flush=True)
        continue
    answer = {{"status":"completed","request_id":request["request_id"],"state_digest":request["state_digest"],
              "question_set_digest":request["question_set_digest"],"manifest_digest":manifest,
              "answers":{{key:0.95 for key in request["question_set"]["question_ids"]}},"input_tokens":50}}
    if behavior == "wrong_request": answer["request_id"] = "foreign"
    if behavior == "wrong_digest": answer["state_digest"] = "f" * 64
    if behavior == "bad_probability": answer["answers"] = {{key:2 for key in answer["answers"]}}
    print(json.dumps(answer),flush=True)
"""
    worker.write_text(code, encoding="utf-8")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory(prefix="ordin-laya-fixture-") as name:
        root = Path(name)
        for directory in ("install", "cwd", "home", "target"):
            (root / directory).mkdir(mode=0o700)
        checkpoint = checkpoint_at(root / "checkpoint")
        worker = root / "install/_laya_worker.py"
        write_fake(worker)
        # A workspace test venv is not an independently protected runtime.
        # This fake stdlib worker uses the external base interpreter instead.
        broker_python = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        runtime = LocalModelRuntime(
            broker_python,
            sha(broker_python),
            worker,
            sha(worker),
            root / "cwd",
            root / "home",
            "d" * 64,
            (root / "target",),
            setup_deadline_ms=2000,
        )
        protected = tmp_path / "protected"
        protected.mkdir(mode=0o700)
        profile = SecurityProfile("fixture", "1", RepositoryScope("fixture/repo", "fixture-v1"))
        path = protected / "profile.json"
        path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
        path.chmod(0o600)
        selection = ProtectedProfileSelection(
            protected.resolve(),
            "profile.json",
            "/trusted/profile.json",
            profile.repository,
            profile.digest,
            sha(path),
            "1",
            "fixture-operator",
            RuntimeCapabilityBoundary(
                "fixture",
                filesystem=(FilesystemCapability("write", "/fixture", "prefix"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            ),
            RuntimeEvidenceSource("fixture", "a" * 64, "fixture-sandbox", "b" * 64),
        )
        approved = load_approved_profile(
            selection, current_repository=profile.repository, active_runtime_policy_digest="b" * 64
        )
        source = HostEvidenceSource(
            "fixture", profile.repository, "a" * 64, 1, "b" * 64, selection.digest
        )
        gate, action, host, _, state = fixture(source=source)
        questions = SemanticInspectionRouter(
            gate, policy=RoutingPolicy(mode="shadow")
        ).questions_for_state(state)[0]
        models = []

        def create(behavior="normal", **changes):
            write_fake(worker, behavior)
            selected_runtime = replace(runtime, worker_sha256=sha(worker), **changes)
            model = LayaDecisionModel(selected_runtime, checkpoint)
            action = local_setup_action(selected_runtime, checkpoint)
            approval = source.record_approval(action, approved, receipt_id="local-setup-approved")
            isolation = source.record_assessment(
                action,
                approved,
                assessment_id="local-isolation",
                invariant_id="semantic.local_scope",
                kind="semantic_local_scope",
                status="satisfied",
            )
            scope = authorize_local_model(
                source, approved, approval, isolation, selected_runtime, checkpoint
            )
            models.append(model)
            return model, scope

        monkeypatch.setenv("OPENAI_API_KEY", "never-inherit-synthetic")
        monkeypatch.setenv("AMBIENT_PRIVATE_TOKEN", "never-inherit-synthetic")
        try:
            yield create, checkpoint, runtime, state, questions, gate, action, host
        finally:
            for model in models:
                model.close()


def test_persistent_typed_worker_and_redacted_metadata(setup):
    create, checkpoint, runtime, state, questions, gate, action, host = setup
    model, scope = create()
    model.initialize(scope)
    pid = model._worker.process.pid
    for _ in range(2):
        result = model.evaluate(state, questions, deadline_ms=500)
        assert result.supportedness == "supported" and result.answers[0].p_yes == 0.95
        assert result.input_digest == state.digest and model._worker.process.pid == pid
    assert model.public_metrics()["calls"] == 2
    assert "never-inherit" not in json.dumps(model.public_metrics())
    with pytest.raises(ValueError):
        LayaDecisionModel(runtime, checkpoint).initialize(scope)
    model.close()
    assert model._worker.process.poll() is not None


@pytest.mark.parametrize(
    "behavior,error",
    [
        ("malformed", "malformed"),
        ("wrong_request", "malformed"),
        ("wrong_digest", "version_mismatch"),
        ("bad_probability", "malformed"),
        ("truncated", "refused"),
        ("overflow", "malformed"),
        ("stderr_overflow", "malformed"),
        ("eval_timeout", "timeout"),
        ("child_hang", "timeout"),
    ],
)
def test_failure_output_timeout_and_descendants_end_worker(setup, behavior, error):
    create, _, _, state, questions, *_ = setup
    model, scope = create(behavior)
    model.initialize(scope)
    result = model.evaluate(state, questions, deadline_ms=500)
    assert result.error_class == error and not result.answers
    assert model._worker.process.poll() is not None
    assert "synthetic-private-text" not in json.dumps(model.public_metrics())


@pytest.mark.parametrize("behavior", ["bad_handshake", "setup_timeout"])
def test_initialization_failure_never_leaves_a_live_worker(setup, behavior):
    create, *_ = setup
    model, scope = create(behavior, setup_deadline_ms=500)
    with pytest.raises((ValueError, TimeoutError)):
        model.initialize(scope)
    assert model._worker.process.poll() is not None


def test_async_cancel_and_call_budget_end_process(setup):
    create, _, _, state, questions, *_ = setup
    model, scope = create("eval_timeout")
    model.initialize(scope)

    async def run():
        pending = asyncio.create_task(model.evaluate_async(state, questions, deadline_ms=5000))
        await asyncio.sleep(0.05)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

    asyncio.run(run())
    assert model._worker.process.poll() is not None


def test_checkpoint_mutation_and_untrusted_config_refused_before_spawn(setup, monkeypatch):
    create, checkpoint, runtime, state, questions, *_ = setup
    checkpoint.verify()
    model, scope = create()
    (checkpoint.root / "model.safetensors").write_bytes(b"changed")
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("bad checkpoint spawned"))
    with pytest.raises(ValueError, match="hash"):
        model.initialize(scope)


def test_tokenizer_vocabulary_not_subject_to_advisory_array_limits():
    packet = {"model": {"vocab": {str(i): i for i in range(10000)}}}
    assert _checkpoint_json(json.dumps(packet).encode()) == packet
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e400}'):
        with pytest.raises(ValueError):
            _checkpoint_json(raw)


def test_no_model_load_or_process_before_explicit_initialize(setup, monkeypatch):
    create, _, _, state, questions, *_ = setup
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("implicit setup"))
    model, scope = create()
    result = model.evaluate(state, questions, deadline_ms=500)
    assert result.error_class == "unavailable"


def test_changed_runtime_binding_and_call_budget_refuse_further_use(setup):
    create, _, _, state, questions, *_ = setup
    model, scope = create(max_calls=1)
    model.initialize(scope)
    assert model.evaluate(state, questions, deadline_ms=500).supportedness == "supported"
    assert model.evaluate(state, questions, deadline_ms=500).error_class == "budget"
    assert model._worker.process.poll() is not None


def test_configuration_change_invalidates_initialized_worker(setup):
    create, _, _, state, questions, *_ = setup
    model, scope = create()
    model.initialize(scope)
    model.runtime = replace(model.runtime, installation_digest="f" * 64)
    result = model.evaluate(state, questions, deadline_ms=500)
    assert result.error_class == "version_mismatch" and model._worker.process.poll() is not None


def test_tokenizer_mutation_and_executable_config_are_not_silently_accepted(setup):
    _, checkpoint, *_ = setup
    config = checkpoint.root / "tokenizer/tokenizer_config.json"
    config.write_text(json.dumps({"tokenizer_class": "TokenizersBackend"}), encoding="utf-8")
    repinned = replace(
        checkpoint, files=tuple((name, sha(checkpoint.root / name)) for name, _ in checkpoint.files)
    )
    with pytest.raises(ValueError, match="mutation"):
        repinned.verify()
    config.write_text(
        json.dumps(
            {"tokenizer_class": "PreTrainedTokenizerFast", "auto_map": {"Tokenizer": "evil.py"}}
        ),
        encoding="utf-8",
    )
    repinned = replace(
        checkpoint, files=tuple((name, sha(checkpoint.root / name)) for name, _ in checkpoint.files)
    )
    with pytest.raises(ValueError, match="custom"):
        repinned.verify()


def test_foreign_state_setup_reuse_and_home_root_refused(setup):
    create, checkpoint, runtime, state, questions, *_ = setup
    model, scope = create()
    with pytest.raises(ValueError):
        model.initialize(scope.__dict__)
    (runtime.private_home / "config.toml").write_text("unreviewed", encoding="utf-8")
    with pytest.raises(ValueError, match="fresh"):
        model.initialize(scope)


def test_pending_setup_cancellation_kills_process(setup):
    create, *_ = setup
    model, scope = create("setup_timeout", setup_deadline_ms=5000)
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.start()
    try:
        with pytest.raises(InterruptedError):
            model.initialize(scope, cancel=cancel)
    finally:
        timer.cancel()
    assert model._worker.process.poll() is not None


def test_already_canceled_setup_never_spawns(setup, monkeypatch):
    create, *_ = setup
    model, scope = create()
    canceled = threading.Event()
    canceled.set()
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("canceled setup spawned"))
    with pytest.raises(InterruptedError):
        model.initialize(scope, cancel=canceled)
    assert model._worker is None
