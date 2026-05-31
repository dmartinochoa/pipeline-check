"""Inline source-line ignore comments.

Extracts ``# pipeline-check: ignore[RULE-ID]`` annotations from raw
file content before YAML/other parsers strip comments. Three
directive variants:

- ``ignore[ID]`` suppresses findings on the same line.
- ``ignore-next-line[ID]`` suppresses findings on the following line.
- ``ignore-file[ID]`` suppresses findings for the entire file.

Multiple rule IDs are comma-separated: ``ignore[GHA-001, GHA-003]``.
An optional ``reason=<text>`` suffix is captured but not enforced.

Both ``#`` and ``//`` comment prefixes are recognized so YAML,
Dockerfile, Groovy (Jenkinsfile), and HCL files all work.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .checks.base import Location

_INLINE_RE = re.compile(
    r"(?:#|//)\s*pipeline-check:\s*"
    r"(ignore|ignore-next-line|ignore-file)"
    r"\[([^\]]+)\]"
    r"(?:\s+reason=(.+))?",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class InlineIgnoreRule:
    """A single inline suppression extracted from a source file."""

    check_id: str
    path: str
    line: int | None = None
    reason: str | None = None


def extract_inline_ignores(
    path: str, text: str,
) -> list[InlineIgnoreRule]:
    """Walk *text* line-by-line and return inline suppression rules."""
    rules: list[InlineIgnoreRule] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        m = _INLINE_RE.search(line)
        if m is None:
            continue
        directive = m.group(1).lower()
        raw_ids = m.group(2)
        reason = m.group(3).strip() if m.group(3) else None
        check_ids = [cid.strip().upper() for cid in raw_ids.split(",") if cid.strip()]
        for cid in check_ids:
            if directive == "ignore":
                rules.append(InlineIgnoreRule(
                    check_id=cid, path=path, line=line_no, reason=reason,
                ))
            elif directive == "ignore-next-line":
                rules.append(InlineIgnoreRule(
                    check_id=cid, path=path, line=line_no + 1, reason=reason,
                ))
            elif directive == "ignore-file":
                rules.append(InlineIgnoreRule(
                    check_id=cid, path=path, line=None, reason=reason,
                ))
    return rules


@dataclass(slots=True)
class InlineIgnoreIndex:
    """Fast lookup structure for inline suppression rules."""

    _by_file_and_line: dict[tuple[str, int], set[str]] = field(
        default_factory=lambda: defaultdict(set),
    )
    _by_file: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set),
    )

    def add(self, rule: InlineIgnoreRule) -> None:
        norm_path = rule.path.replace("\\", "/")
        if rule.line is None:
            self._by_file[norm_path].add(rule.check_id)
        else:
            self._by_file_and_line[(norm_path, rule.line)].add(rule.check_id)

    def matches(
        self,
        check_id: str,
        resource: str,
        locations: list[Location],
    ) -> bool:
        cid = check_id.upper()
        norm_resource = resource.replace("\\", "/")
        if cid in self._by_file.get(norm_resource, set()):
            return True
        for loc in locations:
            norm_path = loc.path.replace("\\", "/")
            if cid in self._by_file.get(norm_path, set()):
                return True
            if loc.start_line is not None:
                key = (norm_path, loc.start_line)
                if cid in self._by_file_and_line.get(key, set()):
                    return True
        return False

    def __bool__(self) -> bool:
        return bool(self._by_file_and_line) or bool(self._by_file)


def build_inline_index(
    rules: list[InlineIgnoreRule],
) -> InlineIgnoreIndex:
    """Build a fast lookup index from extracted inline rules."""
    index = InlineIgnoreIndex()
    for rule in rules:
        index.add(rule)
    return index
