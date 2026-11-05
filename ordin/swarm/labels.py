"""Small conservative sensitivity lattice, configured by protected host policy."""

from dataclasses import dataclass


SENSITIVE_LABELS = frozenset({"secret", "pii", "private_code"})
LABELS = SENSITIVE_LABELS | {"public", "unclassified"}


@dataclass(frozen=True, slots=True)
class Sensitivity:
    labels: tuple[str, ...] = ("unclassified",)

    def __post_init__(self) -> None:
        if (
            type(self.labels) is not tuple
            or not 1 <= len(self.labels) <= len(LABELS)
            or any(type(v) is not str or v not in LABELS for v in self.labels)
            or tuple(sorted(set(self.labels))) != self.labels
            or ("public" in self.labels and len(self.labels) != 1)
        ):
            raise ValueError("invalid canonical sensitivity labels")

    @property
    def sensitive(self) -> bool:
        return bool(SENSITIVE_LABELS.intersection(self.labels))

    @property
    def known(self) -> bool:
        return "unclassified" not in self.labels

    def join(self, *others: "Sensitivity") -> "Sensitivity":
        if len(others) > 64 or any(type(v) is not Sensitivity for v in others):
            raise ValueError("bounded typed sensitivity labels required")
        values = set(self.labels)
        for other in others:
            other.__post_init__()
            values.update(other.labels)
        if len(values) > 1:
            values.discard("public")
        return Sensitivity(tuple(sorted(values)))
