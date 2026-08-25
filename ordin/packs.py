from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import PACK_LIST_SCHEMA_VERSION, PACK_MANIFEST_SCHEMA_VERSION


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATA_ROOT = ROOT / "data"
PACKAGE_DATA_ROOT = Path(__file__).resolve().parent / "resources"
DATA_ROOT = SOURCE_DATA_ROOT if SOURCE_DATA_ROOT.exists() else PACKAGE_DATA_ROOT
PACKS_ROOT = DATA_ROOT / "packs"
PACK_ENV_VAR = "ORDIN_PACKS"


@dataclass(frozen=True)
class CommandPack:
    name: str
    version: str
    description: str
    root: Path
    enabled_by_default: bool
    command_files: tuple[str, ...]
    risk_rule_files: tuple[str, ...]
    effect_catalog_files: tuple[str, ...]
    analyzers: tuple[str, ...]
    manifest: dict[str, Any]

    def as_dict(self, loaded: bool) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "loaded": loaded,
            "enabled_by_default": self.enabled_by_default,
            "command_count": len(self.command_files),
            "risk_rule_file_count": len(self.risk_rule_files),
            "effect_catalog_file_count": len(self.effect_catalog_files),
            "analyzers": list(self.analyzers),
        }


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _string_list(value: Any, field: str, pack_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"pack {pack_name!r} field {field!r} must be a list of strings")
    return tuple(value)


def discover_packs() -> list[CommandPack]:
    if not PACKS_ROOT.exists():
        return []
    packs: list[CommandPack] = []
    seen: set[str] = set()
    for directory in sorted(path for path in PACKS_ROOT.iterdir() if path.is_dir()):
        manifest_path = directory / "pack.json"
        if not manifest_path.exists():
            continue
        payload = _load_json(manifest_path)
        if not isinstance(payload, dict):
            raise ValueError(f"pack manifest {manifest_path} must be a JSON object")
        name = payload.get("name")
        version = payload.get("version")
        description = payload.get("description", "")
        if not isinstance(name, str) or not name:
            raise ValueError(f"pack manifest {manifest_path} requires a non-empty name")
        if name in seen:
            raise ValueError(f"duplicate command pack name: {name}")
        if not isinstance(version, str) or not version:
            raise ValueError(f"pack {name!r} requires a non-empty version")
        if not isinstance(description, str):
            raise ValueError(f"pack {name!r} description must be a string")
        enabled_by_default = payload.get("enabled_by_default", False)
        if not isinstance(enabled_by_default, bool):
            raise ValueError(f"pack {name!r} enabled_by_default must be boolean")
        packs.append(
            CommandPack(
                name=name,
                version=version,
                description=description,
                root=directory,
                enabled_by_default=enabled_by_default,
                command_files=_string_list(payload.get("commands", []), "commands", name),
                risk_rule_files=_string_list(payload.get("risk_rules", []), "risk_rules", name),
                effect_catalog_files=_string_list(
                    payload.get("effect_catalogs", []), "effect_catalogs", name
                ),
                analyzers=_string_list(payload.get("analyzers", []), "analyzers", name),
                manifest=payload,
            )
        )
        seen.add(name)
    return packs


def configured_pack_names(packs: Iterable[CommandPack] | None = None) -> set[str]:
    pack_list = list(discover_packs() if packs is None else packs)
    configured = os.environ.get(PACK_ENV_VAR)
    if configured is None:
        return {pack.name for pack in pack_list if pack.enabled_by_default}
    configured = configured.strip()
    if configured == "*":
        return {pack.name for pack in pack_list}
    if not configured:
        return set()
    return {item.strip() for item in configured.split(",") if item.strip()}


def unknown_configured_pack_names(
    packs: Iterable[CommandPack] | None = None,
) -> set[str]:
    pack_list = list(discover_packs() if packs is None else packs)
    known = {pack.name for pack in pack_list}
    return configured_pack_names(pack_list) - known


def enabled_packs() -> list[CommandPack]:
    packs = discover_packs()
    enabled = configured_pack_names(packs)
    return [pack for pack in packs if pack.name in enabled]


def is_pack_enabled(name: str) -> bool:
    return any(pack.name == name for pack in enabled_packs())


def _safe_relative_path(pack: CommandPack, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"pack {pack.name!r} contains unsafe relative path {relative!r}")
    return pack.root / candidate


def load_pack_commands(pack: CommandPack) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for relative in pack.command_files:
        payload = _load_json(_safe_relative_path(pack, relative))
        if not isinstance(payload, dict):
            raise ValueError(f"pack {pack.name!r} command file {relative!r} must be an object")
        commands.append(payload)
    return commands


def load_pack_risk_rules(pack: CommandPack) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for relative in pack.risk_rule_files:
        payload = _load_json(_safe_relative_path(pack, relative))
        if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
            raise ValueError(f"pack {pack.name!r} risk rule file {relative!r} is invalid")
        rules.extend(rule for rule in payload["rules"] if isinstance(rule, dict))
    return rules


def load_pack_effect_catalog(pack: CommandPack) -> dict[str, dict[str, Any]]:
    effects: dict[str, dict[str, Any]] = {}
    for relative in pack.effect_catalog_files:
        payload = _load_json(_safe_relative_path(pack, relative))
        raw = payload.get("effects") if isinstance(payload, dict) else None
        if not isinstance(raw, dict):
            raise ValueError(f"pack {pack.name!r} effect catalog {relative!r} is invalid")
        for name, definition in raw.items():
            if isinstance(name, str) and isinstance(definition, dict):
                effects[name] = definition
    return effects


def pack_file_errors(packs: Iterable[CommandPack] | None = None) -> list[str]:
    errors: list[str] = []
    pack_list = list(discover_packs() if packs is None else packs)
    for pack in pack_list:
        if pack.root.name != pack.name:
            errors.append(
                f"pack {pack.name!r} directory name must match manifest name; got {pack.root.name!r}"
            )
        for field, paths in (
            ("commands", pack.command_files),
            ("risk_rules", pack.risk_rule_files),
            ("effect_catalogs", pack.effect_catalog_files),
        ):
            for relative in paths:
                try:
                    path = _safe_relative_path(pack, relative)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if not path.is_file():
                    errors.append(f"pack {pack.name!r} {field} file does not exist: {relative!r}")
    for missing in sorted(unknown_configured_pack_names(pack_list)):
        errors.append(f"configured command pack does not exist: {missing!r}")
    return sorted(set(errors))


def pack_list_payload() -> dict[str, Any]:
    packs = discover_packs()
    enabled = configured_pack_names(packs)
    return {
        "schema_version": PACK_LIST_SCHEMA_VERSION,
        "packs": [pack.as_dict(loaded=pack.name in enabled) for pack in packs],
    }


def pack_manifest_schema_version() -> str:
    return PACK_MANIFEST_SCHEMA_VERSION
