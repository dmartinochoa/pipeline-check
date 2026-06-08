"""Strict YAML loading helpers.

pyyaml's default mapping behavior keeps the *last* value when a key
appears twice, silently discarding the earlier declaration. For the
user-facing files this project loads, config files and ignore files,
that's a trap: a duplicated ``pipeline:`` key or a repeated
``resource:`` under one ignore rule hides half the declared intent
without a warning. We raise at load time instead so the typo surfaces.

The check fires only on *explicit* duplicate keys, the ones the user
literally wrote twice. A YAML merge key that is then overridden locally
(``<<: *anchor`` followed by a key that the anchor also defines) is
valid YAML and a common DRY pattern; stock pyyaml keeps the explicit
value, and so do we. Rejecting it would discard the whole file over
correct input, which is exactly the silent data loss this loader exists
to prevent.
"""
from __future__ import annotations

from typing import Any

import yaml

_MERGE_TAG = "tag:yaml.org,2002:merge"


class DupKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects explicitly duplicated mapping keys."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        # Validate against the keys the user wrote *before* flattening any
        # ``<<:`` merge keys. A merge that re-supplies a locally-overridden
        # key is legal and must not count as a duplicate.
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == _MERGE_TAG:
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:
                # Unhashable key (e.g. a list). Let the stock constructor
                # raise its own "unhashable key" error below.
                continue
            if duplicate:
                mark = key_node.start_mark
                raise yaml.constructor.ConstructorError(
                    None, None,
                    f"duplicate key {key!r} at line {mark.line + 1}, "
                    f"column {mark.column + 1}",
                    mark,
                )
            seen.add(key)
        # Defer to the stock merge-aware construction, which flattens the
        # merge keys and applies last-wins so an explicit key overrides the
        # merged one.
        return super().construct_mapping(node, deep=deep)


def safe_load_strict(text: str) -> Any:
    """YAML load that raises on duplicate mapping keys."""
    return yaml.load(text, Loader=DupKeyLoader)


def safe_load_all_strict(text: str) -> list[Any]:
    """Parse a multi-document YAML stream, raising on duplicate keys.

    The multi-doc counterpart of :func:`safe_load_strict`. Used by the
    autofix round-trip gate: stock ``yaml.safe_load_all`` accepts a
    duplicate mapping key (last-wins) and would wave through corrupt
    fixer output that silently drops the earlier value.
    """
    return list(yaml.load_all(text, Loader=DupKeyLoader))
