from __future__ import annotations

import re
from string import Formatter

from .slots import extract_slots


FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def template_fields(template: str) -> set[str]:
    fields: set[str] = set()
    for _, field_name, _, _ in Formatter().parse(template):
        if field_name and FIELD_RE.match(field_name):
            fields.add(field_name)
    return fields


def render_template(template: str, slots: dict[str, str]) -> str | None:
    fields = template_fields(template)
    missing = [field for field in fields if field not in slots]
    if missing:
        return None
    return template.format(**slots)


def suggest_commands(entry: dict, query: str, limit: int = 3) -> list[dict[str, str]]:
    extracted_slots = extract_slots(query)
    suggestions: list[dict[str, str]] = []

    for template in entry.get("templates", []):
        slots = {
            str(key): str(value)
            for key, value in template.get("safe_defaults", {}).items()
        }
        slots.update(extracted_slots)
        command = render_template(template["command"], slots)
        if command is None:
            continue
        suggestions.append(
            {
                "command": command,
                "description": template.get("description", ""),
            }
        )
        if len(suggestions) >= limit:
            break

    return suggestions
