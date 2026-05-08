"""Tiny jsonpath subset for the custom-rule DSL.

A full jsonpath implementation (`jsonpath-ng`, `jsonpath-rw`) is a
non-trivial dep. The DSL only needs the path-traversal subset that
covers the rule shapes in :mod:`docs/writing_a_custom_rule.md`:

    $                       — root document
    .field                  — literal field access
    ['key']                 — quoted field access (keys with dashes/dots)
    [N]                     — list index
    [*]                     — list wildcard

That's enough for "for every container, assert image matches a
regex" — the dominant pattern in the built-in rule catalog. Recursive
descent (``..``), filters (``?``), slicing, and union (``,``) are
deliberately out — when someone needs them, they should write the
rule in Python.

The compiled-once-then-applied shape is a list of "step" callables.
Each step takes the current node and yields zero or more child
nodes, so a path like ``$.containers[*].image`` runs as
``root → containers → list[*] → image`` on every match.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any


class JsonPathError(ValueError):
    """Raised when a jsonpath expression fails to parse."""


# A step yields ``(value,)`` tuples — wrapping in a tuple keeps the
# loop in :func:`iter_matches` straightforward and lets us extend to
# carry path-of-match info later without changing the protocol.
@dataclass(frozen=True, slots=True)
class _Step:
    kind: str          # "field" | "index" | "wildcard"
    value: Any = None  # field name (str) or list index (int); None for wildcard


@dataclass(frozen=True, slots=True)
class CompiledPath:
    """A parsed jsonpath, ready to apply against any document."""

    expression: str
    steps: tuple[_Step, ...]

    def find(self, doc: Any) -> list[Any]:
        """Return every value reachable from *doc* by walking ``steps``.

        Missing fields, non-list/non-dict intermediate values, and
        out-of-range indices yield zero matches rather than raising.
        Type-mismatches are common in rule evaluation (a workflow
        with no ``jobs`` key) and shouldn't crash the scan.
        """
        return list(_apply(doc, self.steps))


def compile_path(expression: str) -> CompiledPath:
    """Parse *expression* into a :class:`CompiledPath`.

    Raises :class:`JsonPathError` with the offending position when the
    expression is malformed. The error message is meant to be readable
    by a rule author who has never seen our parser code.
    """
    if not isinstance(expression, str):
        raise JsonPathError(
            f"jsonpath must be a string, got {type(expression).__name__}"
        )
    if not expression:
        raise JsonPathError("jsonpath is empty")
    if not expression.startswith("$"):
        raise JsonPathError(
            f"jsonpath must start with '$' (got {expression!r})"
        )
    steps: list[_Step] = []
    pos = 1
    n = len(expression)
    while pos < n:
        ch = expression[pos]
        if ch == ".":
            # ``.field`` — read until the next ``.`` or ``[``.
            # ``.*`` is the wildcard convenience form, equivalent to ``[*]``.
            pos += 1
            if pos >= n or expression[pos] in ".[":
                raise JsonPathError(
                    f"jsonpath {expression!r}: empty field after '.' at "
                    f"position {pos}"
                )
            if expression[pos] == "*":
                steps.append(_Step("wildcard"))
                pos += 1
                continue
            field, pos = _read_ident(expression, pos)
            if not _IDENT_RE.match(field):
                raise JsonPathError(
                    f"jsonpath {expression!r}: unquoted field {field!r} "
                    f"is not a valid identifier; use [\"...\"] for keys "
                    f"with dashes/dots"
                )
            steps.append(_Step("field", field))
        elif ch == "[":
            close = expression.find("]", pos)
            if close == -1:
                raise JsonPathError(
                    f"jsonpath {expression!r}: unterminated '[' at "
                    f"position {pos}"
                )
            inner = expression[pos + 1:close].strip()
            if inner == "*":
                steps.append(_Step("wildcard"))
            elif inner.startswith(("'", '"')) and inner.endswith(inner[0]):
                # Quoted field name. Strip the quotes; reject empty.
                key = inner[1:-1]
                if not key:
                    raise JsonPathError(
                        f"jsonpath {expression!r}: empty quoted key at "
                        f"position {pos}"
                    )
                steps.append(_Step("field", key))
            else:
                # Numeric index.
                try:
                    idx = int(inner)
                except ValueError as exc:
                    raise JsonPathError(
                        f"jsonpath {expression!r}: expected '*', "
                        f"'\"key\"', or integer index inside [] at "
                        f"position {pos}, got {inner!r}"
                    ) from exc
                steps.append(_Step("index", idx))
            pos = close + 1
        else:
            raise JsonPathError(
                f"jsonpath {expression!r}: unexpected character "
                f"{ch!r} at position {pos}"
            )
    return CompiledPath(expression=expression, steps=tuple(steps))


def _read_ident(expression: str, start: int) -> tuple[str, int]:
    """Read an unquoted identifier from *start* until a step terminator."""
    i = start
    n = len(expression)
    while i < n and expression[i] not in ".[":
        i += 1
    return expression[start:i], i


# Whitelisted identifier shape for unquoted field steps. Keys outside
# this shape (e.g. ``image-pull-secret``) must be quoted via
# ``['image-pull-secret']``.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _apply(doc: Any, steps: Iterable[_Step]) -> Iterator[Any]:
    """Generator over every value reachable by walking *steps* from *doc*."""
    nodes: list[Any] = [doc]
    for step in steps:
        next_nodes: list[Any] = []
        if step.kind == "field":
            field = step.value
            for node in nodes:
                if isinstance(node, dict) and field in node:
                    next_nodes.append(node[field])
        elif step.kind == "index":
            idx = step.value
            for node in nodes:
                if isinstance(node, list) and -len(node) <= idx < len(node):
                    next_nodes.append(node[idx])
        elif step.kind == "wildcard":
            for node in nodes:
                if isinstance(node, list):
                    next_nodes.extend(node)
                elif isinstance(node, dict):
                    next_nodes.extend(node.values())
        nodes = next_nodes
        if not nodes:
            return
    yield from nodes


__all__ = ["CompiledPath", "JsonPathError", "compile_path"]
