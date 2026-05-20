"""Predicate evaluator for the custom-rule DSL.

A predicate is a recursive YAML structure built from leaf operators
(``eq``, ``regex``, ``exists``, …) and boolean glue (``all_of``,
``any_of``, ``not``). It compiles into a callable
``Predicate(node) -> bool`` that takes the current node (the result
of one ``for_each`` iteration) and returns True when the rule should
*pass* on this node.

The DSL is "fail when assert is False", if ``assert: { eq: ... }``
evaluates to False on a node, that node is recorded as an offender
and the finding fails. This keeps user rules readable: they describe
the *correct* state and the engine surfaces violations.

Leaf operators
==============

Every leaf carries a ``path:`` (a jsonpath relative to the iterated
node) and an op-specific argument. Paths default to the iterated
node itself (``$``) when omitted.

  eq          path, value         → first match equals value
  ne          path, value         → first match != value
  gt/lt/gte/lte path, value       → numeric comparison
  regex       path, pattern       → first string match satisfies pattern
  not_regex   path, pattern       → first string match does NOT satisfy
  in          path, values        → first match is in values
  not_in      path, values        → first match is NOT in values
  exists      path                → at least one match
  missing     path                → zero matches
  len_eq/_gt/_lt path, value      → list/string length comparison

Boolean glue
============

  all_of: [PRED, PRED, ...]       → True iff every child True
  any_of: [PRED, PRED, ...]       → True iff at least one child True
  not:    PRED                    → invert child

Empty / multi-match handling
============================

``eq`` / ``regex`` / ``in`` / ``gt`` etc. evaluate against the
*first* match of ``path``. Zero matches = predicate is False (so
``eq`` on a missing field is "not equal", which feeds the offender
list naturally). ``exists`` / ``missing`` answer the multi-match
case explicitly.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .jsonpath import CompiledPath, JsonPathError, compile_path


class PredicateError(ValueError):
    """Raised when a predicate spec is malformed."""


# A predicate function: takes the iterated node, returns True/False.
Predicate = Callable[[Any], bool]


# ── Predicate compilation ──────────────────────────────────────────


def compile_predicate(spec: Any, where: str = "assert") -> Predicate:
    """Compile *spec* into a callable Predicate.

    *where* is a breadcrumb string used in error messages so a
    malformed nested predicate points at its position
    (``assert.all_of[1].regex`` rather than just "assert").
    """
    if not isinstance(spec, dict):
        raise PredicateError(
            f"{where}: predicate must be a mapping, got "
            f"{type(spec).__name__}"
        )
    if len(spec) != 1:
        raise PredicateError(
            f"{where}: predicate must have exactly one key "
            f"(an operator name), got {sorted(spec)}"
        )
    op, arg = next(iter(spec.items()))
    if op == "all_of":
        return _compile_all_of(arg, where)
    if op == "any_of":
        return _compile_any_of(arg, where)
    if op == "not":
        return _compile_not(arg, where)
    leaf = _LEAF_OPS.get(op)
    if leaf is None:
        valid = sorted(set(_LEAF_OPS) | {"all_of", "any_of", "not"})
        raise PredicateError(
            f"{where}: unknown operator {op!r}. Valid: {', '.join(valid)}"
        )
    return leaf(arg, f"{where}.{op}")


def _compile_all_of(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, list):
        raise PredicateError(
            f"{where}.all_of: must be a list of predicates, got "
            f"{type(arg).__name__}"
        )
    children = [
        compile_predicate(child, f"{where}.all_of[{i}]")
        for i, child in enumerate(arg)
    ]
    if not children:
        raise PredicateError(f"{where}.all_of: list must be non-empty")

    def _eval(node: Any) -> bool:
        return all(child(node) for child in children)

    return _eval


def _compile_any_of(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, list):
        raise PredicateError(
            f"{where}.any_of: must be a list of predicates, got "
            f"{type(arg).__name__}"
        )
    children = [
        compile_predicate(child, f"{where}.any_of[{i}]")
        for i, child in enumerate(arg)
    ]
    if not children:
        raise PredicateError(f"{where}.any_of: list must be non-empty")

    def _eval(node: Any) -> bool:
        return any(child(node) for child in children)

    return _eval


def _compile_not(arg: Any, where: str) -> Predicate:
    inner = compile_predicate(arg, f"{where}.not")

    def _eval(node: Any) -> bool:
        return not inner(node)

    return _eval


# ── Leaf operators ─────────────────────────────────────────────────


def _resolve_path(arg: dict[str, Any], where: str) -> CompiledPath:
    raw = arg.get("path", "$")
    if not isinstance(raw, str) or not raw:
        raise PredicateError(f"{where}: 'path' must be a non-empty string")
    # Bare-name shorthand: ``path: image`` is sugar for ``path: $.image``.
    # Anything else starting without ``$`` is rejected with a hint so the
    # author doesn't accidentally write ``path: ".image"`` and wonder why
    # nothing matches.
    if not raw.startswith("$"):
        raw = f"$.{raw}"
    try:
        return compile_path(raw)
    except Exception as exc:
        raise PredicateError(f"{where}: invalid path: {exc}") from exc


def _first_match(path: CompiledPath, node: Any) -> tuple[Any, bool]:
    """Return ``(value, found)`` for the first match of *path* on *node*."""
    matches = path.find(node)
    if not matches:
        return None, False
    return matches[0], True


def _eq_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict) or "value" not in arg:
        raise PredicateError(f"{where}: requires 'path' (optional) and 'value'")
    path = _resolve_path(arg, where)
    expected = arg["value"]

    def _eval(node: Any) -> bool:
        actual, ok = _first_match(path, node)
        return ok and actual == expected

    return _eval


def _ne_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict) or "value" not in arg:
        raise PredicateError(f"{where}: requires 'path' (optional) and 'value'")
    path = _resolve_path(arg, where)
    expected = arg["value"]

    def _eval(node: Any) -> bool:
        actual, ok = _first_match(path, node)
        # Missing != value (vacuous truth choice, matches `eq` semantics).
        return not ok or actual != expected

    return _eval


def _make_cmp_op(name: str, cmp: Callable[[Any, Any], bool]) -> Callable[[Any, str], Predicate]:
    def _factory(arg: Any, where: str) -> Predicate:
        if not isinstance(arg, dict) or "value" not in arg:
            raise PredicateError(
                f"{where}: requires 'path' (optional) and 'value'"
            )
        path = _resolve_path(arg, where)
        expected = arg["value"]
        if not isinstance(expected, (int, float)):
            raise PredicateError(
                f"{where}: 'value' must be numeric for {name}, got "
                f"{type(expected).__name__}"
            )

        def _eval(node: Any) -> bool:
            actual, ok = _first_match(path, node)
            if not ok or not isinstance(actual, (int, float)):
                return False
            return cmp(actual, expected)

        return _eval
    return _factory


# Limits applied to user-supplied ``regex`` / ``not_regex`` patterns
# in custom rules. Custom rule files are sometimes fetched from a
# shared "platform" repo, so a compromised feed could ship a
# catastrophic-backtracking pattern that hangs the scanner.
# Python's stdlib ``re`` has no native timeout, so we bound complexity
# at the edges: cap the pattern source length (longer patterns are
# almost always a smell), and cap the haystack size the pattern runs
# against. 100KB covers realistic YAML node values; anything bigger
# isn't getting matched literally anyway.
_MAX_REGEX_PATTERN_LEN = 500
_MAX_REGEX_HAYSTACK_BYTES = 100_000


def _regex_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict) or "pattern" not in arg:
        raise PredicateError(f"{where}: requires 'path' (optional) and 'pattern'")
    path = _resolve_path(arg, where)
    pattern_src = arg["pattern"]
    if not isinstance(pattern_src, str):
        raise PredicateError(
            f"{where}: 'pattern' must be a string, got "
            f"{type(pattern_src).__name__}"
        )
    if len(pattern_src) > _MAX_REGEX_PATTERN_LEN:
        raise PredicateError(
            f"{where}: pattern length {len(pattern_src)} exceeds the "
            f"{_MAX_REGEX_PATTERN_LEN}-char cap. Patterns this long "
            f"are typically a sign of catastrophic-backtracking shapes; "
            f"split the rule or simplify."
        )
    try:
        pattern = re.compile(pattern_src)
    except re.error as exc:
        raise PredicateError(
            f"{where}: invalid regex {pattern_src!r}: {exc}"
        ) from exc

    def _eval(node: Any) -> bool:
        actual, ok = _first_match(path, node)
        if not ok or not isinstance(actual, str):
            return False
        # Bound the haystack so a quadratic-backtracking pattern can
        # only burn time proportional to the cap, not the full doc.
        return pattern.search(actual[:_MAX_REGEX_HAYSTACK_BYTES]) is not None

    return _eval


def _not_regex_op(arg: Any, where: str) -> Predicate:
    inner = _regex_op(arg, where)

    def _eval(node: Any) -> bool:
        return not inner(node)

    return _eval


def _in_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict) or "values" not in arg:
        raise PredicateError(f"{where}: requires 'path' (optional) and 'values'")
    if not isinstance(arg["values"], list):
        raise PredicateError(f"{where}: 'values' must be a list")
    path = _resolve_path(arg, where)
    values = arg["values"]

    def _eval(node: Any) -> bool:
        actual, ok = _first_match(path, node)
        return ok and actual in values

    return _eval


def _not_in_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict) or "values" not in arg:
        raise PredicateError(f"{where}: requires 'path' (optional) and 'values'")
    if not isinstance(arg["values"], list):
        raise PredicateError(f"{where}: 'values' must be a list")
    path = _resolve_path(arg, where)
    values = arg["values"]

    def _eval(node: Any) -> bool:
        actual, ok = _first_match(path, node)
        # Missing field is "not in" anything, matches `ne` semantics.
        return not ok or actual not in values

    return _eval


def _exists_op(arg: Any, where: str) -> Predicate:
    if not isinstance(arg, dict):
        raise PredicateError(f"{where}: requires 'path'")
    path = _resolve_path(arg, where)

    def _eval(node: Any) -> bool:
        return bool(path.find(node))

    return _eval


def _missing_op(arg: Any, where: str) -> Predicate:
    inner = _exists_op(arg, where)

    def _eval(node: Any) -> bool:
        return not inner(node)

    return _eval


def _make_len_op(name: str, cmp: Callable[[int, int], bool]) -> Callable[[Any, str], Predicate]:
    def _factory(arg: Any, where: str) -> Predicate:
        if not isinstance(arg, dict) or "value" not in arg:
            raise PredicateError(
                f"{where}: requires 'path' (optional) and 'value'"
            )
        path = _resolve_path(arg, where)
        expected = arg["value"]
        if not isinstance(expected, int):
            raise PredicateError(
                f"{where}: 'value' must be an integer for {name}, got "
                f"{type(expected).__name__}"
            )

        def _eval(node: Any) -> bool:
            actual, ok = _first_match(path, node)
            if not ok or not isinstance(actual, (list, str, dict)):
                return False
            return cmp(len(actual), expected)

        return _eval
    return _factory


_LEAF_OPS: dict[str, Callable[[Any, str], Predicate]] = {
    "eq": _eq_op,
    "ne": _ne_op,
    "gt":  _make_cmp_op("gt",  lambda a, b: a >  b),
    "lt":  _make_cmp_op("lt",  lambda a, b: a <  b),
    "gte": _make_cmp_op("gte", lambda a, b: a >= b),
    "lte": _make_cmp_op("lte", lambda a, b: a <= b),
    "regex": _regex_op,
    "not_regex": _not_regex_op,
    "in": _in_op,
    "not_in": _not_in_op,
    "exists": _exists_op,
    "missing": _missing_op,
    "len_eq": _make_len_op("len_eq", lambda a, b: a == b),
    "len_gt": _make_len_op("len_gt", lambda a, b: a >  b),
    "len_lt": _make_len_op("len_lt", lambda a, b: a <  b),
}


# ── Description template renderer ──────────────────────────────────


_TEMPLATE_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


@dataclass(frozen=True, slots=True)
class CompiledTemplate:
    """A description template with `{{ jsonpath }}` placeholders."""

    raw: str
    parts: tuple[tuple[str, CompiledPath | None], ...]

    def render(self, node: Any, ambient: dict[str, Any] | None = None) -> str:
        """Render against *node* with optional *ambient* variables.

        Bare-name precedence: ``{{ name }}`` resolves to the iterated
        node's ``$.name`` first, falling back to ``ambient["name"]``
        only if the node has no such field. The intuition is that the
        rule author iterates *over the offender*, the container, the
        step, so that node should win for any field it carries.
        Ambient (``kind``, ``namespace``, the manifest-level ``name``)
        is the fallback for fields that don't exist on the iterated
        node.

        ``{{ $.image }}`` is always evaluated as a path, no ambient
        fallback. Missing values render as ``?`` rather than raising —
        a typo in a template should not abort the scan.
        """
        out: list[str] = []
        amb = ambient or {}
        for literal, path in self.parts:
            out.append(literal)
            if path is None:
                continue
            expr = path.expression
            if not expr.startswith("$"):
                # Bare-name: try the iterated node first, then ambient.
                fallback = compile_path(f"$.{expr}")
                matches = fallback.find(node)
                if matches:
                    out.append(_format(matches[0]))
                elif expr in amb:
                    out.append(_format(amb[expr]))
                else:
                    out.append("?")
            else:
                matches = path.find(node)
                out.append(_format(matches[0]) if matches else "?")
        return "".join(out)


def compile_template(text: str) -> CompiledTemplate:
    """Parse a description template into its alternating literal/path parts.

    A template like ``"image {{ image }} not allowed"`` compiles to
    three parts: literal ``"image "``, path ``image``, literal
    ``" not allowed"``. The parser is forgiving, unmatched ``{{``
    or ``}}`` in the literal text are passed through.
    """
    parts: list[tuple[str, CompiledPath | None]] = []
    pos = 0
    for match in _TEMPLATE_RE.finditer(text):
        before = text[pos:match.start()]
        expr = match.group(1).strip()
        # Bare-name shortcut: `{{ name }}` → resolve as ambient or $.<name>.
        # Path expressions starting with `$` go through compile_path verbatim.
        try:
            if expr.startswith("$"):
                path = compile_path(expr)
            elif _IDENT_BARE_RE.match(expr) or "." in expr or "[" in expr:
                # Treat as a path-shaped expression. Bare identifiers
                # remain bare so the renderer can check ambient first;
                # qualified expressions compile right away.
                path = compile_path(expr if expr.startswith("$") else f"$.{expr}")
                if _IDENT_BARE_RE.match(expr):
                    # Keep the original bare form so the renderer can
                    # check ambient before falling back to $.<name>.
                    path = CompiledPath(expression=expr, steps=path.steps)
            else:
                path = None
        # ``compile_path`` raises ``JsonPathError`` (a ``ValueError``
        # subclass) for malformed expressions; the renderer falls back
        # to a literal in that case. Anything else escaping from here
        # is a parser bug, not a user-input shape, so let it propagate.
        except JsonPathError:
            path = None
        parts.append((before, path))
        pos = match.end()
    parts.append((text[pos:], None))
    return CompiledTemplate(raw=text, parts=tuple(parts))


_IDENT_BARE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _format(value: Any) -> str:
    if value is None:
        return "?"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return repr(value)


# ── Convenience: compile + apply a full rule body ──────────────────


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """Compiled (for_each, assert, description) body of a custom rule."""

    for_each: CompiledPath
    predicate: Predicate
    description: CompiledTemplate

    def apply(
        self,
        doc: Any,
        ambient: dict[str, Any] | None = None,
    ) -> tuple[bool, list[str]]:
        """Walk *for_each* and collect offender description strings.

        Returns ``(passed, offenders)``. ``passed`` is True when every
        node satisfied the predicate (or there were no nodes to
        evaluate). ``offenders`` carries the rendered description of
        each failing node so the orchestrator can roll them into the
        finding's description.
        """
        offenders: list[str] = []
        for node in self.for_each.find(doc):
            if not self.predicate(node):
                offenders.append(self.description.render(node, ambient))
        return (not offenders, offenders)


def compile_rule_body(
    for_each: str,
    assert_spec: Any,
    description: str,
) -> CompiledRule:
    """Compile the three user-supplied pieces of a rule body."""
    try:
        path = compile_path(for_each)
    except Exception as exc:
        raise PredicateError(f"for_each: {exc}") from exc
    pred = compile_predicate(assert_spec, where="assert")
    tmpl = compile_template(description)
    return CompiledRule(for_each=path, predicate=pred, description=tmpl)


__all__ = [
    "CompiledRule",
    "CompiledTemplate",
    "Predicate",
    "PredicateError",
    "compile_predicate",
    "compile_rule_body",
    "compile_template",
]
