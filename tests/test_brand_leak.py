"""Guard against the old codename `pipelineguard` re-entering the project.

The published name is **pipeline-check** (see ``pyproject.toml`` and
the console script). An earlier draft used `pipelineguard`, and 91
instances of that codename leaked into autofix TODO markers, doc
examples, and test assertions before the rebrand. Every leaked
marker that lands in autofix output stamps the wrong name into
customer codebases as a durable comment, so this guard exists to
keep the bug from drifting back in.

Pattern: scan every tracked ``.py`` / ``.md`` / ``.yml`` / ``.yaml``
/ ``.toml`` file for the literal token ``pipelineguard`` (case-
insensitive). The token is unique enough that no word-boundary or
stem handling is needed — if it appears anywhere, that's a leak.

CHANGELOG.md is exempt because release notes describing rebrands
need to name the codename being retired (so `git log` searches and
archeological reads remain useful). Code / config / runtime-doc
files are not exempt: those are exactly the surfaces a re-leak
would damage. If you find yourself wanting to mention the old
codename in a non-CHANGELOG file, that is the signal to think
again.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: The forbidden token. Matched case-insensitively so PipelineGuard,
#: PIPELINEGUARD, etc. are all caught.
FORBIDDEN = "pipelineguard"

#: Files exempt from the scan.
#: - The guard test itself has to spell the token to test for it.
#: - CHANGELOG.md is the project's archeological record; release
#:   notes about rebrands need to name the codename they retire.
EXEMPT_FILES: frozenset[str] = frozenset({
    "test_brand_leak.py",
    "CHANGELOG.md",
})

EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".venv", "node_modules", "_site", "_site_test", "site",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__",
    "dist", "build", ".git", ".agents", ".claude",
})

SCAN_EXTS: frozenset[str] = frozenset({".py", ".md", ".yml", ".yaml", ".toml", ".sh"})


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


def test_no_pipelineguard_brand_leak():
    """Fail if the old `pipelineguard` codename appears in any
    tracked source / doc / config / fixture file.

    The published name is `pipeline-check`. The old codename used to
    leak through autofix TODO markers (37 sites), test assertions
    (53), doc examples (2), and the CLI manual (1). It got
    rebranded out in one pass; this guard keeps it out.
    """
    pattern = re.compile(re.escape(FORBIDDEN), re.IGNORECASE)
    offenders: list[str] = []
    for p in _scan_files():
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            rel = p.relative_to(REPO)
            offenders.append(f"{rel}:{line_no}: '{m.group(0)}'")
    assert not offenders, (
        f"\nFound {len(offenders)} occurrence(s) of the old codename "
        f"'{FORBIDDEN}'. The published name is 'pipeline-check' "
        "(see pyproject.toml). Replace each occurrence — autofix "
        "TODO markers, doc examples, and test assertions all need "
        "the new brand. Offenders:\n  "
        + "\n  ".join(offenders[:20])
        + ("\n  ..." if len(offenders) > 20 else "")
    )
