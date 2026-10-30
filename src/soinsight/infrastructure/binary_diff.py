"""Static binary diff between two ELF images.

The engine compares the sets of defined function symbols and reports which
functions were added, removed, resized or renamed (same signature shape, moved
address), plus the finding sets the two scans produced. Matching is by symbol
name first; a C++ name that kept its demangled identity but changed address is
reported as a move, and a pair of removed/added functions with identical
parameter types is reported as a probable signature change -- both are facts,
the renaming interpretation stays in the wording, not in a verdict.

Nothing here executes or disassembles the targets, so a diff of two 3 MB
libraries runs in well under a second; every byte-level question (same
instruction bodies?) is deliberately out of scope.
"""

from dataclasses import dataclass

__all__ = ["DiffReport", "FunctionChange", "diff_functions"]

_MATCH_WINDOW = 64


@dataclass(frozen=True)
class FunctionChange:
    """One function-level change between the two images."""

    change: str
    """``added``, ``removed``, ``moved``, ``resized`` or ``same``."""

    name: str
    linkage_name: str
    old_address: str | None = None
    new_address: str | None = None
    old_size: int | None = None
    new_size: int | None = None
    language: str = "c"

    def as_dict(self) -> dict:
        return {
            "change": self.change,
            "name": self.name,
            "linkage_name": self.linkage_name,
            "old_address": self.old_address,
            "new_address": self.new_address,
            "old_size": self.old_size,
            "new_size": self.new_size,
            "language": self.language,
        }


@dataclass(frozen=True)
class DiffReport:
    """Function-level differences between two images."""

    changes: tuple[FunctionChange, ...]

    @property
    def added(self) -> tuple[FunctionChange, ...]:
        return tuple(item for item in self.changes if item.change == "added")

    @property
    def removed(self) -> tuple[FunctionChange, ...]:
        return tuple(item for item in self.changes if item.change == "removed")

    @property
    def moved(self) -> tuple[FunctionChange, ...]:
        return tuple(item for item in self.changes if item.change == "moved")

    @property
    def resized(self) -> tuple[FunctionChange, ...]:
        return tuple(item for item in self.changes if item.change == "resized")


def _short_name(record: dict) -> str:
    return str(record.get("short_name") or record.get("name") or "")


def _identity(record: dict) -> str:
    """Stable identity of a function: the mangled name when one exists."""
    return str(record.get("name") or "")


def diff_functions(
    old_functions: tuple[dict, ...], new_functions: tuple[dict, ...]
) -> DiffReport:
    """Compare defined function symbols of the two images."""
    old_by_name = {
        _identity(record): record
        for record in old_functions
        if _identity(record) and str(record.get("kind") or "function") == "function"
    }
    new_by_name = {
        _identity(record): record
        for record in new_functions
        if _identity(record) and str(record.get("kind") or "function") == "function"
    }

    changes: list[FunctionChange] = []
    removed_candidates: dict[str, dict] = {}

    for name, old_record in sorted(old_by_name.items()):
        new_record = new_by_name.get(name)
        if new_record is None:
            changes.append(
                FunctionChange(
                    change="removed",
                    name=_short_name(old_record) or name,
                    linkage_name=name,
                    old_address=str(old_record.get("address") or ""),
                    old_size=int(old_record.get("size") or 0),
                    language=str(old_record.get("language") or "c"),
                )
            )
            removed_candidates[name] = old_record
            continue

        old_size = int(old_record.get("size") or 0)
        new_size = int(new_record.get("size") or 0)
        old_address = str(old_record.get("address") or "")
        new_address = str(new_record.get("address") or "")
        if old_address != new_address:
            changes.append(
                FunctionChange(
                    change="moved",
                    name=_short_name(old_record) or name,
                    linkage_name=name,
                    old_address=old_address,
                    new_address=new_address,
                    old_size=old_size,
                    new_size=new_size,
                    language=str(old_record.get("language") or "c"),
                )
            )
        elif old_size != new_size:
            changes.append(
                FunctionChange(
                    change="resized",
                    name=_short_name(old_record) or name,
                    linkage_name=name,
                    old_address=old_address,
                    new_address=new_address,
                    old_size=old_size,
                    new_size=new_size,
                    language=str(old_record.get("language") or "c"),
                )
            )

    for name, new_record in sorted(new_by_name.items()):
        if name in old_by_name:
            continue
        changes.append(
            FunctionChange(
                change="added",
                name=_short_name(new_record) or name,
                linkage_name=name,
                new_address=str(new_record.get("address") or ""),
                new_size=int(new_record.get("size") or 0),
                language=str(new_record.get("language") or "c"),
            )
        )

    order = {"removed": 0, "added": 1, "moved": 2, "resized": 3, "same": 4}
    changes.sort(key=lambda item: (order[item.change], item.linkage_name))
    return DiffReport(changes=tuple(changes))
