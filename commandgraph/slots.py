from __future__ import annotations

import re


PORT_RE = re.compile(r"\b(?:port\s*)?([1-9][0-9]{1,4})\b", re.IGNORECASE)
PATH_RE = re.compile(r"(?:^|\s)((?:\.{1,2}|~|/)[^\s]+|[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)")
QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]")
WILDCARD_RE = re.compile(r"\b([\w.-]*[*?][\w.*?-]*)\b")
URL_RE = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
HOST_RE = re.compile(
    r"\b(?:host|domain|server|endpoint)\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", re.IGNORECASE
)


def _valid_port(value: str) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except ValueError:
        return False


def extract_slots(text: str) -> dict[str, str]:
    slots: dict[str, str] = {}

    url_match = URL_RE.search(text)
    if url_match:
        slots["url"] = url_match.group(0)
        slots["host"] = re.sub(r"^https?://", "", slots["url"], flags=re.IGNORECASE).split("/")[0]

    host_match = HOST_RE.search(text)
    if host_match:
        slots["host"] = host_match.group(1)

    port_match = PORT_RE.search(text)
    if port_match and _valid_port(port_match.group(1)):
        slots["port"] = port_match.group(1)

    quoted = QUOTED_RE.search(text)
    if quoted:
        slots["pattern"] = quoted.group(1)

    wildcard = WILDCARD_RE.search(text)
    if wildcard:
        slots["pattern"] = wildcard.group(1)

    path_match = PATH_RE.search(text)
    if path_match:
        slots["path"] = path_match.group(1)

    depth_match = re.search(r"\b(?:depth|max-depth|levels?)\s+([0-9]+)\b", text, re.IGNORECASE)
    if depth_match:
        slots["depth"] = depth_match.group(1)

    named_match = re.search(r"\b(?:named|name|called)\s+([A-Za-z0-9_.*-]+)\b", text, re.IGNORECASE)
    if named_match and "pattern" not in slots:
        slots["pattern"] = named_match.group(1)

    package_match = re.search(
        r"\b(?:install|uninstall|remove)\s+package\s+([A-Za-z0-9_.@/-]+)\b", text, re.IGNORECASE
    )
    if package_match:
        slots["package"] = package_match.group(1)

    process_match = re.search(
        r"\b(?:kill|stop|find)\s+(?:process\s+)?([A-Za-z0-9_.-]+)\b", text, re.IGNORECASE
    )
    if process_match and not process_match.group(1).isdigit():
        slots["process"] = process_match.group(1)

    branch_match = re.search(r"\bbranch\s+([A-Za-z0-9_.@/-]+)\b", text, re.IGNORECASE)
    if branch_match:
        slots["branch"] = branch_match.group(1)

    return slots
