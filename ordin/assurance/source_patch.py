"""Construct an exact single-file patch artifact in memory; never modify a checkout."""

import difflib
import hashlib
from dataclasses import dataclass, field

from ._files import read_scoped_file
from ._json import digest
from .inventory import AuthorizedRepository, verify_source_reference
from .models import JsonRecord, RepositoryScope, SourceReference
from .validation_models import FindingValidation, _ValidationAuthority
from .validation import _issue


@dataclass(frozen=True)
class SourcePatchProposal(JsonRecord):
    SCHEMA = "assurance_source_patch"
    NESTED = {"repository": RepositoryScope, "source": SourceReference}
    proposal_id: str
    validation_digest: str
    repository: RepositoryScope
    source: SourceReference
    candidate_file_digest: str
    patch_digest: str
    patch_bytes: int
    applied: bool = False
    review_required: bool = True
    _patch: bytes = field(default=b"", repr=False, compare=False)
    _authority: _ValidationAuthority | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if (
            not isinstance(self._authority, _ValidationAuthority)
            or self._authority.payload_digest != self.digest
            or not isinstance(self._patch, bytes)
            or len(self._patch) != self.patch_bytes
            or hashlib.sha256(self._patch).hexdigest() != self.patch_digest
        ):
            raise ValueError("source patch requires actual inspected proposal bytes")

    def private_patch(self):
        """Explicit private review/export; source context may contain sensitive code."""
        return self._patch.decode("utf-8")

    def public_dict(self):
        packet = self.as_dict()
        packet["repository"] = self.repository.digest
        packet["source"] = self.source.digest
        packet["schema_version"] = "ordin.assurance_source_patch_summary.v1"
        packet["report_digest"] = self.digest
        return packet


def propose_source_patch(scope, validation, reference, replacement):
    if (
        not isinstance(scope, AuthorizedRepository)
        or not isinstance(reference, SourceReference)
        or not isinstance(validation, FindingValidation)
        or validation.result != "confirmed"
        or scope.repository != validation.repository
        or not verify_source_reference(scope, reference)
        or not isinstance(replacement, str)
    ):
        raise ValueError(
            "source patch requires confirmed scoped validation and an exact selected source"
        )
    new = replacement.encode("utf-8")
    old = read_scoped_file(scope.root, reference.path, maximum=65536)
    if len(new) > 65536 or hashlib.sha256(old).hexdigest() != reference.content_digest:
        raise ValueError("source patch bytes changed or exceed proposal limits")
    if b"\x00" in old or b"\x00" in new:
        raise ValueError("source patch requires UTF-8 text")
    chunks = difflib.unified_diff(
        old.decode("utf-8").splitlines(keepends=True),
        replacement.splitlines(keepends=True),
        fromfile="a/" + reference.path,
        tofile="b/" + reference.path,
        n=3,
    )
    patch = "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
        for line in chunks
    ).encode("utf-8")
    if not patch or len(patch) > 131072:
        raise ValueError("source patch has no change or exceeds bounded artifact size")
    return _issue(
        SourcePatchProposal,
        dict(
            proposal_id="patch:"
            + digest(
                "source_patch_selection",
                [validation.digest, reference.digest, hashlib.sha256(new).hexdigest()],
            )[:24],
            validation_digest=validation.digest,
            repository=scope.repository,
            source=reference,
            candidate_file_digest=hashlib.sha256(new).hexdigest(),
            patch_digest=hashlib.sha256(patch).hexdigest(),
            patch_bytes=len(patch),
            applied=False,
            review_required=True,
            _patch=patch,
        ),
    )
