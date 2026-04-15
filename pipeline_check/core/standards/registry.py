"""Registry for compliance standards."""
from __future__ import annotations

from .base import ControlRef, Standard

_REGISTRY: dict[str, Standard] = {}


def register(standard: Standard) -> None:
    if not standard.name:
        raise ValueError("Standard.name must be a non-empty string.")
    _REGISTRY[standard.name.lower()] = standard


def get(name: str) -> Standard | None:
    return _REGISTRY.get(name.lower())


def available() -> list[str]:
    return sorted(_REGISTRY.keys())


def resolve(names: list[str] | None = None) -> list[Standard]:
    """Return the selected standards, or every registered standard if *names* is None."""
    if names is None:
        return [_REGISTRY[n] for n in sorted(_REGISTRY.keys())]
    out: list[Standard] = []
    for name in names:
        std = get(name)
        if std is None:
            raise ValueError(
                f"Unknown standard '{name}'. Available: {', '.join(available()) or 'none'}"
            )
        out.append(std)
    return out


def resolve_for_check(check_id: str, standards: list[Standard] | None = None) -> list[ControlRef]:
    """Aggregate ControlRefs for *check_id* across every given standard.

    When *standards* is None, uses every registered standard.
    """
    if standards is None:
        standards = resolve()
    refs: list[ControlRef] = []
    for std in standards:
        refs.extend(std.refs_for(check_id))
    return refs
