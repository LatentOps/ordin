from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class EnvironmentInfo:
    os: str
    distro_id: str | None = None
    distro_like: tuple[str, ...] = ()
    version_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "os": self.os,
            "distro_id": self.distro_id,
            "distro_like": list(self.distro_like),
            "version_id": self.version_id,
        }


@dataclass(frozen=True)
class CommandAvailability:
    installed: bool | None
    executable_path: str | None
    platform_compatible: bool | None
    reason: str
    score_adjustment: float


def normalize_os_name(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("linux"):
        return "linux"
    if normalized in {"darwin", "mac", "macos", "osx"}:
        return "darwin"
    if normalized.startswith("win") or normalized in {"windows", "cygwin"}:
        return "windows"
    return normalized or "unknown"


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def environment_from_os_release(
    os_name: str,
    os_release_text: str | None = None,
) -> EnvironmentInfo:
    normalized_os = normalize_os_name(os_name)
    if normalized_os != "linux" or not os_release_text:
        return EnvironmentInfo(os=normalized_os)

    payload = parse_os_release(os_release_text)
    distro_id = payload.get("ID")
    distro_like = tuple(
        item.strip().lower()
        for item in payload.get("ID_LIKE", "").split()
        if item.strip()
    )
    return EnvironmentInfo(
        os=normalized_os,
        distro_id=distro_id.lower() if distro_id else None,
        distro_like=distro_like,
        version_id=payload.get("VERSION_ID"),
    )


def detect_environment(
    *,
    os_name: str | None = None,
    os_release_path: Path = Path("/etc/os-release"),
) -> EnvironmentInfo:
    platform_name = os_name or sys.platform
    normalized_os = normalize_os_name(platform_name)
    os_release_text: str | None = None
    if normalized_os == "linux":
        try:
            os_release_text = os_release_path.read_text(encoding="utf-8")
        except OSError:
            os_release_text = None
    return environment_from_os_release(normalized_os, os_release_text)


def platform_compatibility(
    entry: dict,
    environment: EnvironmentInfo,
) -> tuple[bool | None, str | None]:
    constraints = entry.get("platforms")
    if not isinstance(constraints, dict) or not constraints:
        return None, None

    allowed_os = {
        str(item).lower()
        for item in constraints.get("os", [])
        if isinstance(item, str)
    }
    if allowed_os and environment.os not in allowed_os:
        return False, f"platform metadata targets {', '.join(sorted(allowed_os))}"

    allowed_ids = {
        str(item).lower()
        for item in constraints.get("distro_ids", [])
        if isinstance(item, str)
    }
    allowed_like = {
        str(item).lower()
        for item in constraints.get("distro_like", [])
        if isinstance(item, str)
    }
    if not allowed_ids and not allowed_like:
        return True, f"platform metadata matches {environment.os}"

    if environment.os != "linux":
        return False, "distribution-specific command is intended for Linux"
    if not environment.distro_id and not environment.distro_like:
        return None, "Linux distribution could not be identified"

    current_family = set(environment.distro_like)
    if environment.distro_id:
        current_family.add(environment.distro_id)
    if current_family & (allowed_ids | allowed_like):
        label = environment.distro_id or "/".join(environment.distro_like)
        return True, f"distribution metadata matches {label}"

    label = environment.distro_id or "/".join(environment.distro_like)
    expected = sorted(allowed_ids | allowed_like)
    return False, (
        f"distribution {label or 'unknown'} does not match "
        f"{', '.join(expected)}"
    )


def command_availability(
    entry: dict,
    *,
    environment: EnvironmentInfo | None = None,
    which: Callable[[str], str | None] | None = None,
) -> CommandAvailability:
    environment = environment or detect_environment()
    resolver = which or shutil.which
    command = str(entry.get("command", "")).strip()

    executable_path: str | None = None
    installed: bool | None = None
    if command:
        executable_path = resolver(command)
        installed = executable_path is not None

    compatible, platform_reason = platform_compatibility(entry, environment)

    # Availability is a bounded ranking signal, never a filter. Semantic intent
    # matching remains dominant while locally useful commands win close calls.
    score_adjustment = 0.0
    reasons: list[str] = []
    if installed is True:
        score_adjustment += 0.60
        reasons.append("available locally")
    elif installed is False:
        score_adjustment -= 0.10
        reasons.append("not found on PATH")

    if compatible is True:
        score_adjustment += 0.20
        if platform_reason:
            reasons.append(platform_reason)
    elif compatible is False:
        score_adjustment -= 0.60
        if platform_reason:
            reasons.append(platform_reason)
    elif platform_reason:
        reasons.append(platform_reason)

    score_adjustment = max(-0.70, min(0.80, score_adjustment))
    return CommandAvailability(
        installed=installed,
        executable_path=executable_path,
        platform_compatible=compatible,
        reason="; ".join(reasons) if reasons else "availability unknown",
        score_adjustment=score_adjustment,
    )
