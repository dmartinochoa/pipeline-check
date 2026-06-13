"""Line-aware YAML loader for pipeline-check.

PyYAML's parsed dicts and lists drop source-line markers by default —
once you call ``yaml.safe_load(text)`` the file/line info is gone, and
checks have to invent it back from regexes. This module wraps the
PyYAML construction layer so every parsed mapping and sequence
remembers the line and column it came from.

Usage
-----

    from pipeline_check.core.checks._yaml_lines import (
        safe_load_yaml_lines,
        safe_load_all_with_lines,
        line_of,
        line_of_item,
    )

    doc = safe_load_yaml_lines(text)
    line_of(doc["jobs"]["build"])         # 1-based source line
    line_of_item(doc["steps"], 3)         # line of steps[3]

How it works
------------

We subclass ``yaml.SafeLoader`` and override ``construct_mapping`` /
``construct_sequence`` to wrap the constructed objects in ``LineDict``
/ ``LineList`` instances that carry ``_line`` / ``_col`` attributes
plus a ``_item_lines`` list aligned with each sequence element. The
hot-path ``safe_load_yaml`` (CSafeLoader-backed) stays untouched for
parsers that don't need lines (the CFN loader, the ignore-file loader,
the strict dup-key loader).

The cost is real but small: pure-Python construction is roughly 2-3x
slower than the C-accelerated path on large workflow files. Providers
that opt in to lines accept that tradeoff in exchange for "click here
to jump to line 47" precision in every reporter and the PR-comment
action.

Multi-doc support
-----------------

``safe_load_all_with_lines(text)`` yields each ``(start_line, doc)``
in stream order so providers like Tekton / Argo / Kubernetes / Helm
can record where each ``---``-separated body began. The line is the
``---`` marker's position (or ``1`` for the first doc when the file
opens without one).
"""
from __future__ import annotations

import warnings as _warnings
from collections.abc import Iterator
from typing import Any

import yaml


class LineDict(dict):  # type: ignore[type-arg]
    """A ``dict`` subclass that remembers its source line and column."""

    __slots__ = ("_line", "_col")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._line: int | None = None
        self._col: int | None = None


class LineList(list):  # type: ignore[type-arg]
    """A ``list`` subclass with line markers per element.

    ``_item_lines[i]`` is the 1-based source line of element ``i``,
    or ``None`` when the element wasn't a YAML node (e.g. spliced in
    by a constructor). ``_line`` / ``_col`` carry the position of
    the sequence header itself.
    """

    __slots__ = ("_line", "_col", "_item_lines", "_item_cols")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._line: int | None = None
        self._col: int | None = None
        self._item_lines: list[int | None] = []
        self._item_cols: list[int | None] = []


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that preserves node start_mark on parsed containers."""

    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False,
    ) -> LineDict:
        # PyYAML's default returns a plain dict; we want our subclass
        # so per-mapping line info has somewhere to live. Re-implement
        # the minimum: walk the node's pairs and call construct_object
        # on each side, raising on non-hashable keys the same way the
        # parent does.
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None, None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )
        self.flatten_mapping(node)
        mapping: LineDict = LineDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping", node.start_mark,
                    f"found unhashable key ({exc})", key_node.start_mark,
                ) from exc
            if key in mapping:
                mark = key_node.start_mark
                _warnings.warn(
                    f"duplicate YAML key {key!r} at line "
                    f"{mark.line + 1}, column {mark.column + 1}",
                    stacklevel=1,
                )
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        mapping._line = node.start_mark.line + 1  # 1-based
        mapping._col = node.start_mark.column + 1
        return mapping

    def construct_sequence(
        self, node: yaml.SequenceNode, deep: bool = False,
    ) -> LineList:
        if not isinstance(node, yaml.SequenceNode):
            raise yaml.constructor.ConstructorError(
                None, None,
                f"expected a sequence node, but found {node.id}",
                node.start_mark,
            )
        out: LineList = LineList()
        for child in node.value:
            out.append(self.construct_object(child, deep=deep))
            out._item_lines.append(child.start_mark.line + 1)
            out._item_cols.append(child.start_mark.column + 1)
        out._line = node.start_mark.line + 1
        out._col = node.start_mark.column + 1
        return out


# PyYAML's built-in constructors call construct_mapping /
# construct_sequence directly, so just subclassing wires up most of
# the recursion. The two special-case map / seq constructors below
# need to use our overrides instead of the parent's because the
# parent caches a plain dict in ``self.constructed_objects`` for
# anchor reuse. We want the line-aware version cached.
def _construct_mapping_top(loader: _LineLoader, node: yaml.MappingNode) -> LineDict:
    return loader.construct_mapping(node, deep=True)


def _construct_sequence_top(loader: _LineLoader, node: yaml.SequenceNode) -> LineList:
    return loader.construct_sequence(node, deep=True)


_LineLoader.add_constructor(
    "tag:yaml.org,2002:map", _construct_mapping_top,
)
_LineLoader.add_constructor(
    "tag:yaml.org,2002:seq", _construct_sequence_top,
)


def safe_load_yaml_lines(text: str) -> Any:
    """Parse YAML preserving line/column markers on dicts and lists."""
    return yaml.load(text, Loader=_LineLoader)


def safe_load_all_with_lines(text: str) -> Iterator[tuple[int, Any]]:
    """Yield ``(start_line, document)`` for each doc in a multi-doc stream.

    ``start_line`` is 1-based; the first document starts at line 1
    when the file opens without a ``---`` marker, or at the line of
    the document's root node otherwise. We pull each document via
    PyYAML's ``check_node`` / ``get_node`` pair so the loader manages
    its own event stream and we just read each root node's
    ``start_mark`` for line attribution.
    """
    loader = _LineLoader(text)
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            # construct_document / dispose are untyped in the
            # types-PyYAML stubs; ignore at call site rather than
            # widening the loader's annotated surface.
            doc = loader.construct_document(node)  # type: ignore[no-untyped-call]
            yield node.start_mark.line + 1, doc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]


def line_of(obj: Any) -> int | None:
    """Return the 1-based source line of *obj*, or ``None``.

    Works on :class:`LineDict` and :class:`LineList`. Returns ``None``
    for plain dicts / lists (e.g. produced by a non-line-aware loader)
    so callers can fall through to the file-level annotation.
    """
    return getattr(obj, "_line", None)


def line_of_item(seq: Any, idx: int) -> int | None:
    """Return the 1-based source line of ``seq[idx]``, or ``None``."""
    if not isinstance(seq, LineList):
        return None
    if 0 <= idx < len(seq._item_lines):
        return seq._item_lines[idx]
    return None
