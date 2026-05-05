"""Strict YAML loading helpers.

pyyaml's default mapping behaviour keeps the *last* value when a key
appears twice, silently discarding the earlier declaration. For the
user-facing files this project loads — config files and ignore files —
that's a trap: a duplicated ``pipeline:`` key or a repeated
``resource:`` under one ignore rule hides half the declared intent
without a warning. We raise at load time instead so the typo surfaces.
"""
from __future__ import annotations

from typing import Any

import yaml


class DupKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                mark = key_node.start_mark
                raise yaml.constructor.ConstructorError(
                    None, None,
                    f"duplicate key {key!r} at line {mark.line + 1}, "
                    f"column {mark.column + 1}",
                    mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def safe_load_strict(text: str) -> Any:
    """YAML load that raises on duplicate mapping keys."""
    return yaml.load(text, Loader=DupKeyLoader)
