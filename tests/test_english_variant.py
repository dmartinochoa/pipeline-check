"""Guard against British spellings landing in the project.

The convention (see ``CLAUDE.md``) is American English everywhere.
This test scans every tracked ``.py`` and ``.md`` file for a known
list of British forms and fails when one is found, with a pointer
to the right American spelling.

Adding a new pair: append to ``PAIRS`` below and to the table in
``CLAUDE.md``. Two skip files are exempt (the converter script and
this test itself) because they intentionally carry both forms.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# (british, american) pairs. Keep in sync with CLAUDE.md and with
# scripts/_apply_american_english.py. Use lower-case forms; the regex
# is case-insensitive.
PAIRS: list[tuple[str, str]] = [
    ("analyse", "analyze"),
    ("analysed", "analyzed"),
    ("analysing", "analyzing"),
    ("analyses", "analyzes"),
    ("analyser", "analyzer"),
    ("artefact", "artifact"),
    ("artefacts", "artifacts"),
    ("behaviour", "behavior"),
    ("behaviours", "behaviors"),
    ("behavioural", "behavioral"),
    ("cancelled", "canceled"),
    ("cancelling", "canceling"),
    ("catalogue", "catalog"),
    ("catalogues", "catalogs"),
    ("cataloguing", "cataloging"),
    ("centre", "center"),
    ("centred", "centered"),
    ("centring", "centering"),
    ("centres", "centers"),
    ("characterise", "characterize"),
    ("characterised", "characterized"),
    ("colour", "color"),
    ("coloured", "colored"),
    ("colours", "colors"),
    ("colouring", "coloring"),
    ("customise", "customize"),
    ("customised", "customized"),
    ("customising", "customizing"),
    ("defence", "defense"),
    ("emphasise", "emphasize"),
    ("emphasised", "emphasized"),
    ("favour", "favor"),
    ("favourite", "favorite"),
    ("favourites", "favorites"),
    ("flavour", "flavor"),
    ("flavours", "flavors"),
    ("grey", "gray"),
    ("honour", "honor"),
    ("humour", "humor"),
    ("initialise", "initialize"),
    ("initialised", "initialized"),
    ("initialising", "initializing"),
    ("labelled", "labeled"),
    ("labelling", "labeling"),
    ("licence", "license"),
    ("localise", "localize"),
    ("localised", "localized"),
    ("maximise", "maximize"),
    ("maximised", "maximized"),
    ("maximising", "maximizing"),
    ("memoise", "memoize"),
    ("memoised", "memoized"),
    ("memoising", "memoizing"),
    ("minimise", "minimize"),
    ("minimised", "minimized"),
    ("minimising", "minimizing"),
    ("modelled", "modeled"),
    ("modelling", "modeling"),
    ("normalise", "normalize"),
    ("normalised", "normalized"),
    ("normalising", "normalizing"),
    ("normalisation", "normalization"),
    ("offence", "offense"),
    ("optimise", "optimize"),
    ("optimised", "optimized"),
    ("optimising", "optimizing"),
    ("organise", "organize"),
    ("organised", "organized"),
    ("organising", "organizing"),
    ("organisation", "organization"),
    ("parametrise", "parameterize"),
    ("parametrised", "parameterized"),
    ("penalise", "penalize"),
    ("penalised", "penalized"),
    ("practise", "practice"),
    ("prioritise", "prioritize"),
    ("prioritised", "prioritized"),
    ("prioritising", "prioritizing"),
    ("programme", "program"),
    ("recognise", "recognize"),
    ("recognised", "recognized"),
    ("recognising", "recognizing"),
    ("rumour", "rumor"),
    ("serialise", "serialize"),
    ("serialised", "serialized"),
    ("signalled", "signaled"),
    ("signalling", "signaling"),
    ("summarise", "summarize"),
    ("summarised", "summarized"),
    ("synchronise", "synchronize"),
    ("synchronised", "synchronized"),
    ("travelling", "traveling"),
    ("utilise", "utilize"),
    ("utilised", "utilized"),
    ("whilst", "while"),
    ("amongst", "among"),
    ("towards", "toward"),
    ("backwards", "backward"),
    ("forwards", "forward"),
    ("upwards", "upward"),
    ("downwards", "downward"),
]

# Files exempt from the scan. Both files intentionally carry the
# British forms: the converter's PAIRS list and this test's PAIRS
# list. CLAUDE.md documents both forms in a table.
EXEMPT_FILES: frozenset[str] = frozenset({
    "_apply_american_english.py",
    "test_english_variant.py",
    "CLAUDE.md",
})

EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".venv", "node_modules", "_site", "_site_test", "site",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__",
    "dist", "build", ".git", ".agents", ".claude",
})

SCAN_EXTS: frozenset[str] = frozenset({".py", ".md", ".yml", ".yaml", ".toml"})


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


@pytest.mark.parametrize("british,american", PAIRS)
def test_no_british_spelling(british: str, american: str):
    """Fail if any tracked source or doc file uses the *british* form."""
    pattern = re.compile(rf"\b{re.escape(british)}\b", re.IGNORECASE)
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
        f"\nFound {len(offenders)} use(s) of British '{british}'. "
        f"Use '{american}' instead (see CLAUDE.md). Offenders:\n  "
        + "\n  ".join(offenders[:20])
        + ("\n  ..." if len(offenders) > 20 else "")
    )
