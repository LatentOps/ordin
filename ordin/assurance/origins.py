"""Host source handles and exact byte-use correlation; neither grants permission."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from ordin.action import ActionEnvelope
from ordin._runtime_json import digest as core_digest

from ._json import validate
from .host import HostEvidenceSource
from .models import JsonRecord, RepositoryScope, SourceReference


@dataclass(frozen=True)
class _OriginAuthority:
    source_key: str
    payload_digest: str


@dataclass(frozen=True)
class InstructionOrigin(JsonRecord):
    """A host declaration of origin/classification, separate from execution evidence."""

    SCHEMA = "assurance_instruction_origin"
    NESTED = {"repository": RepositoryScope, "source": SourceReference}
    origin_id: str
    source_key: str
    principal: str
    repository: RepositoryScope
    session_digest: str
    epoch: int
    kind: str
    classification: str
    content_digest: str
    span_digest: str
    span_start: int
    span_end: int
    source: SourceReference | None = None
    parent_action_digest: str | None = None
    _authority: _OriginAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.span_start > self.span_end or self.span_end > 1_048_576:
            raise ValueError("source span bounds invalid")
        if self.source is not None and (
            self.kind != "repository_file"
            or self.source.revision != self.repository.revision
            or self.source.content_digest != self.content_digest
        ):
            raise ValueError("source reference does not match declared repository bytes")
        if (
            not isinstance(self._authority, _OriginAuthority)
            or self._authority.source_key != self.source_key
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("instruction origin requires a protected host source")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> InstructionOrigin:
        raise ValueError("JSON origin labels cannot authenticate a source")


@dataclass(frozen=True)
class SourceUse(JsonRecord):
    """Exact bytes supplied in a proposed action, not proof of persuasion or execution."""

    SCHEMA = "assurance_source_use"
    use_id: str
    source_key: str
    origin_digest: str
    action_digest: str
    argument_path: tuple[str, ...]
    value_digest: str
    usage: str = "data_argument"
    _authority: _OriginAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.argument_path or self.argument_path[0] != "parameters":
            raise ValueError("source-use path must identify bounded action parameters")
        if (
            not isinstance(self._authority, _OriginAuthority)
            or self._authority.source_key != self.source_key
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("source use requires a protected host source")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SourceUse:
        raise ValueError("JSON source-use claims cannot authenticate data flow")


@dataclass(frozen=True)
class SourceProvenance(JsonRecord):
    """Explicit host collection coverage, not a conclusion from absent records."""

    SCHEMA = "assurance_source_provenance"
    source_key: str
    action_digest: str
    origin_digests: tuple[str, ...]
    use_digests: tuple[str, ...]
    completeness: str = "partial"
    _authority: _OriginAuthority | None = field(
        default=None, repr=False, compare=False, kw_only=True
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(set(self.origin_digests)) != len(self.origin_digests) or len(
            set(self.use_digests)
        ) != len(self.use_digests):
            raise ValueError("duplicate provenance handle")
        if (
            not isinstance(self._authority, _OriginAuthority)
            or self._authority.source_key != self.source_key
            or self._authority.payload_digest != self.digest
        ):
            raise ValueError("provenance coverage requires a protected host collector")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SourceProvenance:
        raise ValueError("JSON cannot authenticate source collection completeness")


def _seal(model, values, source_key):
    preview = object.__new__(model)
    for key, value in values.items():
        object.__setattr__(preview, key, value)
    object.__setattr__(preview, "_authority", None)
    validate(model.SCHEMA, preview.as_dict())
    return model(**values, _authority=_OriginAuthority(source_key, preview.digest))


def register_instruction_origin(
    source: HostEvidenceSource,
    *,
    origin_id: str,
    kind: str,
    classification: str,
    content: str | bytes,
    span_start: int = 0,
    span_end: int | None = None,
    source_reference: SourceReference | None = None,
    parent_action_digest: str | None = None,
) -> InstructionOrigin:
    """Protected host API: call after obtaining actual bytes and identifying their origin.

    Classification is host supplied, not inferred from role/trust words in the
    content. Authorized user instructions still confer no operator policy or
    execution authority. No bytes are read from disk or retained in the handle.
    """
    if not isinstance(source, HostEvidenceSource) or not isinstance(content, (str, bytes)):
        raise ValueError("source origin requires a typed host source and bounded bytes")
    if len(content) > 1_048_576:
        raise ValueError("source bytes/span limit exceeded")
    try:
        raw = content.encode("utf-8") if isinstance(content, str) else content
    except UnicodeError:
        raise ValueError("source bytes encoding invalid") from None
    end = len(raw) if span_end is None else span_end
    if (
        len(raw) > 1_048_576
        or type(span_start) is not int
        or type(end) is not int
        or not 0 <= span_start <= end <= len(raw)
    ):
        raise ValueError("source bytes/span limit exceeded")
    values = dict(
        origin_id=origin_id,
        source_key=source.key,
        principal=source.principal,
        repository=source.repository,
        session_digest=source.session_digest,
        epoch=source.epoch,
        kind=kind,
        classification=classification,
        content_digest=hashlib.sha256(raw).hexdigest(),
        span_digest=hashlib.sha256(raw[span_start:end]).hexdigest(),
        span_start=span_start,
        span_end=end,
        source=source_reference,
        parent_action_digest=parent_action_digest,
    )
    return _seal(InstructionOrigin, values, source.key)


def _selected_value(action: ActionEnvelope, path: tuple[str, ...]) -> bytes:
    if (
        not isinstance(action, ActionEnvelope)
        or not isinstance(path, (list, tuple))
        or not 1 <= len(path) <= 8
        or any(not isinstance(key, str) for key in path)
        or path[0] != "parameters"
    ):
        raise ValueError("invalid source-use action path")
    value: Any = action.as_dict()
    for key in path:
        if isinstance(value, Mapping) and key in value:
            value = value[key]
        elif (
            isinstance(value, (tuple, list))
            and key.isascii()
            and key.isdigit()
            and len(key) <= 3
            and int(key) < len(value)
        ):
            value = value[int(key)]
        else:
            raise ValueError("source-use field unavailable")
    if not isinstance(value, str):
        raise ValueError("source-use field requires exact UTF-8 text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("source-use field encoding invalid") from None
    if len(raw) > 1_048_576:
        raise ValueError("source-use field byte limit exceeded")
    return raw


def correlate_source_use(
    source: HostEvidenceSource,
    origin: InstructionOrigin,
    action: ActionEnvelope,
    *,
    use_id: str,
    argument_path: tuple[str, ...],
    usage: str = "data_argument",
) -> SourceUse:
    """Record only an exact source-span/action-field byte match in the same host scope."""
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(origin, InstructionOrigin)
        or origin.source_key != source.key
    ):
        raise ValueError("source handle belongs to another host scope")
    raw = _selected_value(action, argument_path)
    value_digest = hashlib.sha256(raw).hexdigest()
    if value_digest != origin.span_digest:
        raise ValueError("source span does not match the proposed action bytes")
    return _seal(
        SourceUse,
        dict(
            use_id=use_id,
            source_key=source.key,
            origin_digest=origin.digest,
            action_digest=core_digest(action.as_dict()),
            argument_path=tuple(argument_path),
            value_digest=value_digest,
            usage=usage,
        ),
        source.key,
    )


def verify_source_use(
    source: HostEvidenceSource, origin: InstructionOrigin, use: SourceUse, action: ActionEnvelope
) -> bool:
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(origin, InstructionOrigin)
        or not isinstance(use, SourceUse)
        or not isinstance(action, ActionEnvelope)
        or origin.source_key != source.key
        or use.source_key != source.key
        or use.origin_digest != origin.digest
        or use.action_digest != core_digest(action.as_dict())
    ):
        return False
    try:
        return (
            hashlib.sha256(_selected_value(action, use.argument_path)).hexdigest()
            == use.value_digest
            == origin.span_digest
        )
    except ValueError:
        return False


def record_source_provenance(
    source: HostEvidenceSource,
    action: ActionEnvelope,
    *,
    origins: tuple[InstructionOrigin, ...] = (),
    uses: tuple[SourceUse, ...] = (),
    completeness: str = "partial",
) -> SourceProvenance:
    """Protected host API; complete means actual instrumented input provenance.

    Exact byte handles cannot model arbitrary transformations. If the collector
    cannot cover derived/unknown inputs, it must declare partial or unknown.
    Absence of a supplied handle never establishes absence of sensitive flow.
    """
    if (
        not isinstance(source, HostEvidenceSource)
        or not isinstance(action, ActionEnvelope)
        or not isinstance(origins, (tuple, list))
        or not isinstance(uses, (tuple, list))
        or len(origins) > 128
        or len(uses) > 128
        or any(not isinstance(v, InstructionOrigin) for v in origins)
        or any(not isinstance(v, SourceUse) for v in uses)
    ):
        raise ValueError("bounded typed source provenance required")
    origin_map = {v.digest: v for v in origins}
    if (
        len(origin_map) != len(origins)
        or any(v.source_key != source.key for v in origins)
        or any(
            use.origin_digest not in origin_map
            or not verify_source_use(source, origin_map[use.origin_digest], use, action)
            for use in uses
        )
    ):
        raise ValueError("source provenance contains uncorrelated handles")
    return _seal(
        SourceProvenance,
        dict(
            source_key=source.key,
            action_digest=core_digest(action.as_dict()),
            origin_digests=tuple(sorted(origin_map)),
            use_digests=tuple(sorted(v.digest for v in uses)),
            completeness=completeness,
        ),
        source.key,
    )
