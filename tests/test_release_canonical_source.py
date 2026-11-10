"""Release inputs are committed blobs, independent of checkout EOL conversion."""

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from scripts import check_swarm_release as source
from tests.test_swarm_release_gate import repository, git


def checkout(original, target, crlf):
    subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=" + os.devnull,
            "clone",
            "--no-hardlinks",
            "--config",
            "core.autocrlf=" + ("true" if crlf else "false"),
            str(original),
            str(target),
        ],
        check=True,
        capture_output=True,
    )
    return target


def test_real_git_lf_and_crlf_checkouts_stage_identical_canonical_bytes(tmp_path):
    root, _ = repository(tmp_path)
    binary = b"\x00owned binary\r\nkeep exact CRLF\r\n"
    (root / "ordin/blob.bin").write_bytes(binary)
    (root / "README.md").write_bytes(b"Owned readme\nsecond line\n")
    (root / "LICENSE").write_bytes(b"Owned license\nsecond line\n")
    with (root / ".gitattributes").open("a", encoding="utf-8") as stream:
        stream.write("*.bin -text\n")
    git(root, "add", ".")
    git(root, "-c", "core.hooksPath=" + os.devnull, "commit", "-qm", "canonical binary fixture")
    revision = git(root, "rev-parse", "HEAD")
    lf, crlf = checkout(root, tmp_path / "lf", False), checkout(root, tmp_path / "crlf", True)
    assert b"\r\n" not in (lf / "ordin/__init__.py").read_bytes()
    assert b"\r\n" in (crlf / "ordin/__init__.py").read_bytes()
    assert (lf / "ordin/blob.bin").read_bytes() == (crlf / "ordin/blob.bin").read_bytes() == binary
    canonical = source.committed_files(lf, revision)
    assert source.committed_files(crlf, revision) == canonical
    assert source.source_identity(lf, revision) == source.source_identity(crlf, revision)
    for name, directory in (("lf-build", lf), ("crlf-build", crlf)):
        target = source.copy_build_source(directory, tmp_path / name)
        for path in (
            "ordin/__init__.py",
            "ordin/blob.bin",
            "README.md",
            "LICENSE",
            "pyproject.toml",
        ):
            assert (target / path).read_bytes() == canonical[path]
    (crlf / "ordin/blob.bin").write_bytes(binary.replace(b"\r\n", b"\n"))
    with pytest.raises(ValueError):
        source.source_identity(crlf, revision)


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_hidden_index_flags_cannot_mask_worktree_tampering(tmp_path, flag):
    root, revision = repository(tmp_path)
    git(root, "update-index", flag, "ordin/__init__.py")
    (root / "ordin/__init__.py").write_text("# changed but hidden from ordinary diff\n")
    with pytest.raises(ValueError, match="index entries"):
        source.source_identity(root, revision)


def test_git_replace_refs_cannot_change_canonical_blob_identity(tmp_path):
    root, revision = repository(tmp_path)
    original = source.committed_files(root, revision)["ordin/__init__.py"]
    old = git(root, "rev-parse", revision + ":ordin/__init__.py")
    replacement = (
        subprocess.check_output(
            ["git", "-C", str(root), "hash-object", "-w", "--stdin"],
            input=b"# owned replacement must not become source\n",
        )
        .decode()
        .strip()
    )
    git(root, "replace", old, replacement)
    assert source.committed_files(root, revision)["ordin/__init__.py"] == original
    assert source.source_identity(root, revision)["commit"] == revision


def test_head_move_during_canonical_capture_cannot_mix_source_identities(tmp_path, monkeypatch):
    root, revision = repository(tmp_path)
    original = source._committed_source

    def moved(directory, selected):
        captured = original(directory, selected)
        git(
            root,
            "-c",
            "core.hooksPath=" + os.devnull,
            "commit",
            "--allow-empty",
            "-qm",
            "owned concurrent head movement",
        )
        return captured

    monkeypatch.setattr(source, "_committed_source", moved)
    with pytest.raises(ValueError, match="HEAD changed"):
        source.source_identity(root, revision)


def test_blob_content_hash_is_checked_even_if_git_batch_is_malformed(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    (root / "owned.bin").write_bytes(b"old")
    oid = hashlib.sha1(b"blob 3\x00old").hexdigest().encode()
    calls = []

    def forged(root, *args, **kwargs):
        calls.append(args[0])
        if args[0] == "ls-tree":
            return b"100644 blob " + oid + b" 3\towned.bin\x00"
        assert args[0] == "cat-file"
        return oid + b" blob 3\nbad\n"

    monkeypatch.setattr(source, "git", forged)
    with pytest.raises(ValueError, match="trusted tree OID"):
        source.committed_files(root, "a" * 40)
    assert calls == ["ls-tree", "cat-file"]


@pytest.mark.parametrize("violation", ["member", "aggregate", "mode"])
def test_tree_limits_and_modes_are_rejected_before_blob_batch_capture(
    tmp_path, monkeypatch, violation
):
    size = source.MAX_SOURCE_FILE_BYTES + 1 if violation == "member" else 1
    mode = b"120000" if violation == "mode" else b"100644"
    if violation == "aggregate":
        monkeypatch.setattr(source, "MAX_SOURCE_BYTES", 0)

    def metadata_only(root, *args, **kwargs):
        assert args[0] == "ls-tree", "blob contents were collected before rejecting the inventory"
        return mode + b" blob " + b"a" * 40 + b" " + str(size).encode() + b"\towned.bin\x00"

    monkeypatch.setattr(source, "git", metadata_only)
    with pytest.raises(ValueError):
        source.committed_files(tmp_path, "b" * 40)


def test_shared_artifact_windows_verification_is_an_attestation_dependency():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text()
    windows = workflow.split("  verify-windows:\n", 1)[1].split("  attest:\n", 1)[0]
    attest = workflow.split("  attest:\n", 1)[1].split("  publish-github:\n", 1)[0]
    assert "needs: build" in windows and "runs-on: windows-latest" in windows
    assert "artifact-ids: ${{ needs.build.outputs.artifact-id }}" in windows
    assert "checkout-index --all --force" in windows and "core.autocrlf=true" in windows
    assert "scripts/release_integrity.py verify --bundle" in windows
    assert "scripts/check_release_bundle_install.py" in windows
    assert "python -I -B" in windows and "@tagArgs" in windows
    assert "needs: [build, verify-windows]" in attest
