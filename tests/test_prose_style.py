"""Guard against AI-essay tic words landing in the project's prose.

The CLAUDE.md prose convention asks the codebase to "read like a
coworker wrote it" and calls out a set of AI-essay tics to avoid. This
test is the sibling of ``test_english_variant.py``: it scans every
tracked ``.py`` and ``.md`` file for the tic words that have **no
legitimate technical meaning** in this codebase and fails when one
lands, so AI-generated docs/rule prose can't reintroduce them.

Deliberately NOT enforced here (the CLAUDE.md still discourages them,
but they carry real technical meanings that make a hard ban produce
false positives):

  - ``robust`` / ``robustness`` — used for genuine code-robustness
    ("the generator stays robust against a missing package", a test's
    "Robustness against malformed predicates" section).
  - ``leverage`` — used as the security noun ("the highest-leverage
    attack vector"; an attacker "leverages" a primitive).

For those two, prefer the simpler word when it reads as filler, but
that judgment is left to review rather than gated here.

Adding a word: append to ``BANNED`` and to the CLAUDE.md prose list.
The two historical records (CHANGELOG / ROADMAP) are exempt because
their past entries are immutable and legitimately quote the words
(e.g. an entry describing the removal of "comprehensive").
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# AI-essay tic words with no legitimate technical use in this codebase.
# Lower-case; the scan is whole-word and case-insensitive. Keep in sync
# with the prose-style list in CLAUDE.md.
BANNED: list[str] = [
    "moreover",
    "furthermore",
    "comprehensive",
    "comprehensively",
    "delve",
    "delves",
    "delving",
    "delved",
]

# Files / names exempt from the scan.
#   - CHANGELOG.md / ROADMAP.md: append-only historical records whose
#     past entries legitimately quote the banned words.
#   - CLAUDE.md: documents the convention (lists the words).
#   - this test: carries the BANNED list.
EXEMPT_FILES: frozenset[str] = frozenset({
    "CHANGELOG.md",
    "ROADMAP.md",
    "CLAUDE.md",
    "test_prose_style.py",
})

EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".venv", "node_modules", "_site", "_site_test", "site",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__",
    "dist", "build", ".git", ".agents", ".claude",
})

# Project prose lives in source and docs. Sample CI configs under
# tests/fixtures (``.yml`` / ``.yaml``) are external content, not the
# project's own prose, so they're out of scope.
SCAN_EXTS: frozenset[str] = frozenset({".py", ".md"})


def _scan_files() -> list[Path]:
    out: list[Path] = []
    for p in REPO.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in SCAN_EXTS:
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        if p.name in EXEMPT_FILES:
            continue
        out.append(p)
    return out


# One whole-word, case-insensitive alternation over every banned word,
# scanned once over the corpus (mirrors test_english_variant's
# single-pass approach).
_COMBINED_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in BANNED) + r")\b",
    re.IGNORECASE,
)


def _offenders(texts: list[tuple[str, str]]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {w: [] for w in BANNED}
    for label, text in texts:
        for m in _COMBINED_RE.finditer(text):
            key = m.group(0).lower()
            line_no = text.count("\n", 0, m.start()) + 1
            buckets.setdefault(key, []).append(
                f"{label}:{line_no}: '{m.group(0)}'"
            )
    return buckets


@pytest.fixture(scope="module")
def repo_offenders() -> dict[str, list[str]]:
    texts: list[tuple[str, str]] = []
    for p in _scan_files():
        try:
            texts.append((str(p.relative_to(REPO)), p.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return _offenders(texts)


@pytest.mark.parametrize("word", BANNED)
def test_no_ai_tic_word(word: str, repo_offenders: dict[str, list[str]]) -> None:
    """Fail if any tracked source or doc file uses an AI-essay tic word."""
    offenders = repo_offenders.get(word, [])
    assert not offenders, (
        f"\nFound {len(offenders)} use(s) of the AI-tic word '{word}'. "
        f"Reword it (see the prose-style note in CLAUDE.md). Offenders:\n  "
        + "\n  ".join(offenders[:20])
        + ("\n  ..." if len(offenders) > 20 else "")
    )


def test_combined_scan_matches_naive() -> None:
    """The single-pass combined scan must match a naive per-word scan."""
    corpus = [
        ("a.py", "Moreover, we delve into it. Furthermore, comprehensive."),
        ("b.md", "A comprehensively robust test that leverages delving."),
        ("c.py", "no tics here, just plain ascii and numbers 123."),
    ]
    naive: dict[str, list[str]] = {w: [] for w in BANNED}
    for label, text in corpus:
        for word in BANNED:
            pat = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
            for m in pat.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                naive[word].append(f"{label}:{line_no}: '{m.group(0)}'")
    assert _offenders(corpus) == naive
