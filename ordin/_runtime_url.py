"""Raw authority character checks; no parsing, normalization, or I/O."""


def has_unsafe_authority_characters(value: str) -> bool:
    """Reject ASCII whitespace/controls and DEL before authority parsing."""
    return any(ord(character) <= 32 or ord(character) == 127 for character in value)
