"""One-shot script: apply British -> American spelling conversions.

Run from the repo root:

    python scripts/_apply_american_english.py

Skips generated and vendored directories (.venv, site, _site, dist,
build, etc.). Applies case-preserving substitution: "Behaviour" stays
title-case, "BEHAVIOUR" stays upper-case.

The pair list mirrors CLAUDE.md. Update both together.
"""
from __future__ import annotations

import re
from pathlib import Path

PAIRS = [
    ("analyse", "analyze"), ("analysed", "analyzed"), ("analysing", "analyzing"),
    ("analyses", "analyzes"), ("analyser", "analyzer"),
    ("artefact", "artifact"), ("artefacts", "artifacts"),
    ("behaviour", "behavior"), ("behaviours", "behaviors"),
    ("behavioural", "behavioral"),
    ("cancelled", "canceled"), ("cancelling", "canceling"),
    ("catalogue", "catalog"), ("catalogues", "catalogs"),
    ("cataloguing", "cataloging"),
    ("centralise", "centralize"), ("centralised", "centralized"),
    ("centralising", "centralizing"), ("centralisation", "centralization"),
    ("centre", "center"), ("centred", "centered"),
    ("centring", "centering"), ("centres", "centers"),
    ("characterise", "characterize"), ("characterised", "characterized"),
    ("colour", "color"), ("coloured", "colored"),
    ("colours", "colors"), ("colouring", "coloring"),
    ("customise", "customize"), ("customised", "customized"),
    ("customising", "customizing"),
    ("defence", "defense"),
    ("emphasise", "emphasize"), ("emphasised", "emphasized"),
    ("favour", "favor"), ("favourite", "favorite"),
    ("favourites", "favorites"),
    ("flavour", "flavor"), ("flavours", "flavors"),
    ("grey", "gray"),
    ("honour", "honor"), ("honours", "honors"),
    ("honoured", "honored"), ("honouring", "honoring"),
    ("humour", "humor"),
    ("initialise", "initialize"), ("initialised", "initialized"),
    ("initialising", "initializing"),
    ("labelled", "labeled"), ("labelling", "labeling"),
    ("licence", "license"),
    ("localise", "localize"), ("localised", "localized"),
    ("maximise", "maximize"), ("maximised", "maximized"),
    ("maximising", "maximizing"),
    ("memoise", "memoize"), ("memoised", "memoized"),
    ("memoising", "memoizing"),
    ("minimise", "minimize"), ("minimised", "minimized"),
    ("minimising", "minimizing"),
    ("modelled", "modeled"), ("modelling", "modeling"),
    ("normalise", "normalize"), ("normalised", "normalized"),
    ("normalising", "normalizing"), ("normalisation", "normalization"),
    ("offence", "offense"),
    ("optimise", "optimize"), ("optimised", "optimized"),
    ("optimising", "optimizing"),
    ("organise", "organize"), ("organised", "organized"),
    ("organising", "organizing"), ("organisation", "organization"),
    ("organisations", "organizations"), ("organisational", "organizational"),
    ("parametrise", "parameterize"), ("parametrised", "parameterized"),
    ("parameterise", "parameterize"), ("parameterised", "parameterized"),
    ("parameterises", "parameterizes"), ("parameterising", "parameterizing"),
    ("unparameterised", "unparameterized"),
    ("penalise", "penalize"), ("penalised", "penalized"),
    ("practise", "practice"),
    ("prioritise", "prioritize"), ("prioritised", "prioritized"),
    ("prioritising", "prioritizing"),
    ("programme", "program"),
    ("recognise", "recognize"), ("recognised", "recognized"),
    ("recognises", "recognizes"),
    ("recognising", "recognizing"), ("recognisable", "recognizable"),
    ("authorise", "authorize"), ("authorised", "authorized"),
    ("authorises", "authorizes"), ("authorising", "authorizing"),
    ("unauthorised", "unauthorized"),
    ("authorisation", "authorization"), ("authorisations", "authorizations"),
    ("rumour", "rumor"),
    ("sanitise", "sanitize"), ("sanitised", "sanitized"),
    ("sanitises", "sanitizes"), ("sanitiser", "sanitizer"),
    ("sanitisers", "sanitizers"), ("sanitising", "sanitizing"),
    ("sanitisation", "sanitization"),
    ("serialise", "serialize"), ("serialised", "serialized"),
    ("signalled", "signaled"), ("signalling", "signaling"),
    ("summarise", "summarize"), ("summarised", "summarized"),
    ("synchronise", "synchronize"), ("synchronised", "synchronized"),
    ("tokenise", "tokenize"), ("tokenised", "tokenized"),
    ("tokenises", "tokenizes"), ("tokeniser", "tokenizer"),
    ("tokenisers", "tokenizers"), ("tokenising", "tokenizing"),
    ("tokenisation", "tokenization"),
    ("generalise", "generalize"), ("generalised", "generalized"),
    ("generalises", "generalizes"), ("generalising", "generalizing"),
    ("specialise", "specialize"), ("specialised", "specialized"),
    ("specialises", "specializes"), ("specialising", "specializing"),
    ("travelling", "traveling"),
    ("utilise", "utilize"), ("utilised", "utilized"),
    ("whilst", "while"), ("amongst", "among"),
    ("towards", "toward"), ("backwards", "backward"),
    ("forwards", "forward"), ("upwards", "upward"),
    ("downwards", "downward"),
]


def _case_preserve(brit: str, amer: str, match: re.Match) -> str:
    s = match.group(0)
    if s.isupper():
        return amer.upper()
    if s[0].isupper():
        return amer[0].upper() + amer[1:]
    return amer


EXCLUDE_DIRS = {
    ".venv", "node_modules", "_site", "_site_test", "site",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__",
    "dist", "build", ".git", ".agents", ".claude",
}
SCAN_EXTS = {".py", ".md", ".yml", ".yaml", ".toml"}


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    total_changes = 0
    total_files = 0
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in SCAN_EXTS:
            continue
        if any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        # Skip the _apply_american_english script itself; the PAIRS list
        # contains every British form we want to remove from the repo.
        if p.name == "_apply_american_english.py":
            continue
        # Skip the test that asserts no British spellings remain. Its
        # PAIRS list intentionally carries both forms.
        if p.name == "test_english_variant.py":
            continue
        # Skip CLAUDE.md. It documents both forms (avoid -> use), and
        # rerunning the converter would erase the "avoid" column.
        if p.name == "CLAUDE.md":
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        new = text
        file_changes = 0
        for brit, amer in PAIRS:
            pattern = re.compile(rf"\b{re.escape(brit)}\b", re.IGNORECASE)
            new, n = pattern.subn(
                lambda m, b=brit, a=amer: _case_preserve(b, a, m),
                new,
            )
            file_changes += n
        if file_changes:
            p.write_text(new, encoding="utf-8", newline="\n")
            print(f"  {file_changes:3d}  {p.relative_to(repo)}")
            total_changes += file_changes
            total_files += 1
    print()
    print(f"Replaced {total_changes} occurrences across {total_files} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
