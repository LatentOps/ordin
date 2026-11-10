"""Release-only executable selection and explicit subprocess privacy envelopes."""

from __future__ import annotations

import os
from pathlib import Path


BASE_KEYS = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
}


def trusted_executable(name: str, *boundaries: Path) -> str:
    if name not in {"git", "gh"}:
        raise ValueError("unsupported release qualification tool")
    current = Path.cwd().resolve()
    excluded = (Path(__file__).resolve().parents[1], *(Path(root).resolve() for root in boundaries))
    filename = name + (".exe" if os.name == "nt" else "")
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(entry)
        if not entry or not directory.is_absolute():
            continue
        try:
            directory = directory.resolve(strict=True)
            candidate = (directory / filename).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            directory == current
            or candidate.parent == current
            or any(
                directory.is_relative_to(root) or candidate.is_relative_to(root)
                for root in excluded
            )
        ):
            continue
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise ValueError("trusted absolute release tool outside source/workspace required: " + name)


def child_environment(workspace: Path) -> dict[str, str]:
    home, temporary = workspace / "home", workspace / "tmp"
    for path in (home, temporary, home / "appdata", home / "localappdata"):
        path.mkdir(mode=0o700)
    result = {key: value for key, value in os.environ.items() if key.upper() in BASE_KEYS}
    result.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(home / "appdata"),
            "LOCALAPPDATA": str(home / "localappdata"),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "TMPDIR": str(temporary),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_NO_INPUT": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
    )
    return result


def qualification_environment() -> dict[str, str]:
    # Only explicit gh qualification calls retain the operator's GH auth/config.
    keys = BASE_KEYS | {
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "TEMP",
        "TMP",
        "TMPDIR",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_CONFIG_DIR",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in keys}


def git_environment() -> dict[str, str]:
    keys = BASE_KEYS | {
        "HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
    }
    result = {key: value for key, value in os.environ.items() if key.upper() in keys}
    result.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.fsmonitor",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_CONFIG_KEY_2": "diff.external",
            "GIT_CONFIG_VALUE_2": "",
        }
    )
    return result
