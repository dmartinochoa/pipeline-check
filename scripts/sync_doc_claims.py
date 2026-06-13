#!/usr/bin/env python3
"""Rewrite the registry-derived numeric doc claims to match the code.

``tests/test_doc_claims.py`` *checks* that the headline counts in the
doc set ("39 providers", "18 compliance standards", "120 autofixers",
"56 attack chains", "1220+ checks", the per-provider "N checks" cells,
and the README architecture ID ranges) agree with the live registries.
This script is the *writer* for the same claims: it derives the numbers
from the registries and bumps every stale literal in one pass, so adding
a rule or a provider no longer means hand-editing README.md, action.yml,
``docs/comparison.md``, CONTRIBUTING.md, and the Docker Hub README by
hand (step 7 of ``scripts/new_rule.py``'s checklist).

    python scripts/sync_doc_claims.py            # rewrite stale claims
    python scripts/sync_doc_claims.py --check     # report drift, write nothing

``--check`` exits non-zero when a claim is stale (the gate
``scripts/preflight.py`` and ``tests/test_doc_claims.py`` already
enforce). The default rewrites.

Semantics: "make the doc pass the test". A claim is only rewritten when
its current value would *fail* ``test_doc_claims`` (exact match for
provider / autofixer / chain / per-row counts; a tolerance band for the
``N+ checks`` floor and the "OWASP plus N frameworks" standards prose).
A claim already inside the accepted set is left untouched, so a run
against an in-sync tree changes nothing.

The count helpers and claim regexes mirror ``tests/test_doc_claims.py``
deliberately. That test validates the docs on every run, so if this
writer ever derives a number the test disagrees with, the test fails:
the test is the guard against this script drifting from it.

Not yet auto-fixed (reported as a manual step in ``--check``): the
``docs/comparison.md`` SCM / OCI composite cells and any architecture
line whose body lists multiple ranges or bare single IDs for one prefix
(the writer only rewrites the common single-range-per-prefix shape).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from pipeline_check.core.autofix import _FIXERS as _AUTOFIXERS  # noqa: E402
from pipeline_check.core.providers import available as _providers_available  # noqa: E402
from pipeline_check.core.standards import available as _standards_available  # noqa: E402

# ──────────────────────────────────────────────────────────────────
# Live counts from the code (mirrors tests/test_doc_claims.py)
# ──────────────────────────────────────────────────────────────────


def _count_providers() -> int:
    return len(_providers_available())


def _count_standards() -> int:
    return len(_standards_available())


def _count_autofixers() -> int:
    return len(_AUTOFIXERS)


def _count_attack_chains() -> int:
    chains_dir = _REPO / "pipeline_check" / "core" / "chains" / "rules"
    if not chains_dir.is_dir():
        return 0
    return sum(
        1 for p in chains_dir.iterdir()
        if p.suffix == ".py" and p.name != "__init__.py" and not p.name.startswith("_")
    )


def _count_rules_in(provider: str) -> int:
    rules_dir = _REPO / "pipeline_check" / "core" / "checks" / provider / "rules"
    if not rules_dir.is_dir():
        return 0
    return sum(
        1 for f in rules_dir.iterdir()
        if f.suffix == ".py" and f.name != "__init__.py" and not f.name.startswith("_")
    )


_CHECK_ID_LITERAL = re.compile(r'check_id="([A-Z]+-\d+)"')


def _count_class_based_check_ids(provider: str) -> int:
    prov_dir = _REPO / "pipeline_check" / "core" / "checks" / provider
    if not prov_dir.is_dir():
        return 0
    ids: set[str] = set()
    for f in prov_dir.rglob("*.py"):
        if "rules" in f.parts or f.name.startswith("_") or f.name == "__init__.py":
            continue
        ids.update(_CHECK_ID_LITERAL.findall(f.read_text(encoding="utf-8")))
    return len(ids)


def _count_total_checks() -> int:
    n = 0
    checks_dir = _REPO / "pipeline_check" / "core" / "checks"
    for prov_dir in checks_dir.iterdir():
        if (prov_dir / "rules").is_dir():
            n += _count_rules_in(prov_dir.name)
    return (
        n
        + _count_class_based_check_ids("terraform")
        + _count_class_based_check_ids("cloudformation")
    )


def _existing_ids_for_prefix(provider: str, prefix: str) -> set[int]:
    rules_dir = _REPO / "pipeline_check" / "core" / "checks" / provider / "rules"
    if not rules_dir.is_dir():
        return set()
    pat = re.compile(rf"^{prefix.lower()}(\d+)_")
    return {int(m.group(1)) for f in rules_dir.iterdir() if (m := pat.match(f.name))}


# ──────────────────────────────────────────────────────────────────
# Claim regexes (mirrors tests/test_doc_claims.py)
# ──────────────────────────────────────────────────────────────────

_PROVIDER_CLAIM = re.compile(r"\b(\d+)\s+(?:CI/CD\s+)?providers?\b", re.IGNORECASE)
_STANDARD_CLAIM = re.compile(
    r"\b(\d+)\s+(?:compliance\s+)?(?:standards?|frameworks?)\b", re.IGNORECASE
)
_AUTOFIXER_CLAIM = re.compile(r"\b(\d+)\s+(?:autofixer|fixer)s?\b", re.IGNORECASE)
_CHAIN_CLAIM = re.compile(
    r"\b(\d+)\s+(?:attack|multi-finding)\s+chains?\b", re.IGNORECASE
)
_CHECK_CLAIM = re.compile(r"\b(\d+)\+\s+checks?\b", re.IGNORECASE)

# Files scanned for aggregate claims. Same list as test_doc_claims.py's
# DOCS_WITH_CLAIMS so the writer covers exactly what the gate checks.
_DOCS_WITH_CLAIMS = [
    "README.md",
    "docs/index.md",
    "action.yml",
    "pyproject.toml",
    "mkdocs.yml",
    "CONTRIBUTING.md",
    ".github/DOCKERHUB.md",
    "docs/usage.md",
]

# README provider-table row label → rules/ slug (subset with a plain
# "<N> checks" fourth column; composite rows handled separately).
_README_PROVIDER_TABLE_ROWS: dict[str, str] = {
    "AWS": "aws", "Azure (live)": "azure_cloud", "GCP (live)": "gcp",
    "Pulumi": "pulumi", "GitHub Actions": "github", "GitLab CI": "gitlab",
    "Bitbucket Pipelines": "bitbucket", "Azure DevOps": "azure",
    "Jenkins": "jenkins", "CircleCI": "circleci",
    "Google Cloud Build": "cloudbuild", "Buildkite": "buildkite",
    "Drone CI": "drone", "Tekton": "tekton", "Argo Workflows": "argo",
    "Argo CD": "argocd", "Dockerfile": "dockerfile", "Kubernetes": "kubernetes",
    "OCI image manifest": "oci", "Maven": "maven", "NuGet": "nuget",
    "Composer": "composer", "Cargo": "cargo", "Go modules": "gomod",
    "RubyGems": "rubygems",
}

_COMPARISON_ROWS: dict[str, str] = {
    "GitHub Actions": "github", "GitLab CI": "gitlab",
    "Jenkins (Declarative + Scripted)": "jenkins", "CircleCI": "circleci",
    "Azure DevOps": "azure", "Bitbucket Pipelines": "bitbucket",
    "Google Cloud Build": "cloudbuild", "Buildkite": "buildkite",
    "Drone CI": "drone", "Tekton": "tekton", "Argo Workflows": "argo",
    "Kubernetes manifests": "kubernetes", "Dockerfile": "dockerfile",
    "Live AWS account scan": "aws",
}


# ──────────────────────────────────────────────────────────────────
# Change tracking
# ──────────────────────────────────────────────────────────────────


class Changer:
    """Accumulates ``(file, description, old, new)`` edits and applies
    them, so ``--check`` and the write path share one code path."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str]] = []  # (rel_path, "X -> Y (label)")
        self.manual: list[str] = []               # un-auto-fixable drift

    def sub_first_number(
        self, text: str, pattern: re.Pattern[str], valid: set[int],
        canonical: int, rel: str, label: str,
    ) -> str:
        """Rewrite the leading number of every *pattern* match whose value
        is not in *valid* to *canonical*. The number is group(1) at the
        start of the match, so the rest of the match is preserved."""
        def repl(m: re.Match[str]) -> str:
            n = int(m.group(1))
            if n in valid:
                return m.group(0)
            self.changes.append((rel, f"{n} -> {canonical} ({label})"))
            return str(canonical) + m.group(0)[len(m.group(1)):]
        return pattern.sub(repl, text)


def _floor10(n: int) -> int:
    return (n // 10) * 10


# ──────────────────────────────────────────────────────────────────
# Per-surface rewriters
# ──────────────────────────────────────────────────────────────────


def _rewrite_aggregate(text: str, rel: str, ch: Changer) -> str:
    providers = _count_providers()
    standards = _count_standards()
    fixers = _count_autofixers()
    chains = _count_attack_chains()
    total = _count_total_checks()
    floor = _floor10(total)
    # ``N+ checks`` is a floor: any value in [total-20, total] passes the
    # test, so only rewrite when it falls outside that band, and then to
    # the rounded-down-to-ten current floor.
    check_valid = set(range(max(0, total - 20), total + 1))
    # Standards prose accepts "OWASP plus (N-1) frameworks" as well.
    text = ch.sub_first_number(text, _PROVIDER_CLAIM, {providers}, providers, rel, "providers")
    text = ch.sub_first_number(text, _STANDARD_CLAIM, {standards, standards - 1}, standards, rel, "standards")
    text = ch.sub_first_number(text, _AUTOFIXER_CLAIM, {fixers}, fixers, rel, "autofixers")
    text = ch.sub_first_number(text, _CHAIN_CLAIM, {chains}, chains, rel, "attack chains")
    text = ch.sub_first_number(text, _CHECK_CLAIM, check_valid, floor, rel, "+checks floor")
    return text


# docs/index.md stat tiles carry the count both as a ``data-count-to``
# attribute and as visible text, split across tags the aggregate regex
# can't see. The test catches them after HTML-stripping; the writer needs
# this targeted form to actually fix them.
_PG_STAT_RE = re.compile(
    r'(data-count-to=")(\d+)("\s*>)(\d+)(\+?)(</div><div class="pg-stat__label">)(Checks|Providers)(</div>)'
)


def _rewrite_index_stat_tiles(text: str, rel: str, ch: Changer) -> str:
    providers = _count_providers()
    total = _count_total_checks()
    floor = _floor10(total)
    check_valid = set(range(max(0, total - 20), total + 1))

    def repl(m: re.Match[str]) -> str:
        label = m.group(7)
        cur = int(m.group(4))
        if label == "Providers":
            target = providers
            if cur == target:
                return m.group(0)
        else:  # Checks (floor)
            if cur in check_valid:
                return m.group(0)
            target = floor
        ch.changes.append((rel, f"{cur} -> {target} (index stat tile: {label})"))
        return (
            m.group(1) + str(target) + m.group(3) + str(target)
            + m.group(5) + m.group(6) + m.group(7) + m.group(8)
        )

    return _PG_STAT_RE.sub(repl, text)


def _rewrite_readme_provider_table(text: str, ch: Changer) -> str:
    for row_name, slug in _README_PROVIDER_TABLE_ROWS.items():
        actual = _count_rules_in(slug)
        pat = re.compile(
            rf"(\|\s*(?:↳\s*)?\*\*{re.escape(row_name)}\*\*[^|]*\|"
            rf"[^|]*\|[^|]*\|\s*)(\d+)(\s+checks?)"
        )
        m = pat.search(text)
        if not m or int(m.group(2)) == actual:
            continue
        ch.changes.append(("README.md", f"{m.group(2)} -> {actual} (table row: {row_name})"))
        text = text[:m.start()] + m.group(1) + str(actual) + m.group(3) + text[m.end():]
    return text


def _rewrite_readme_aws_arch_line(text: str, ch: Changer) -> str:
    actual = _count_rules_in("aws")
    pat = re.compile(r"(├──\s*aws/rules/\s*#\s*)(\d+)(\s+rule-based\s+checks?)", re.IGNORECASE)
    m = pat.search(text)
    if m and int(m.group(2)) != actual:
        ch.changes.append(("README.md", f"{m.group(2)} -> {actual} (aws architecture line)"))
        text = text[:m.start()] + m.group(1) + str(actual) + m.group(3) + text[m.end():]
    return text


_RANGE_LINE_RE = re.compile(
    r"^(?P<indent>\s*├──\s*)(?P<provider>\w+)(?P<mid>/rules/\s*#\s*)(?P<body>.+)$",
    re.MULTILINE,
)
_RANGE_PIECE_RE = re.compile(
    r"\b(?P<prefix>[A-Z][A-Z0-9]*)-(?P<lo>\d+)"
    r"(?:(?P<sep>\s*\.\.\s*(?:(?P=prefix)-)?)(?P<hi>\d+))?"
)


def _rewrite_readme_arch_ranges(text: str, ch: Changer) -> str:
    """Bump the high end of each single-range-per-prefix architecture
    claim ("GHA-001 .. GHA-NNN"). Lines listing multiple ranges or bare
    singles for one prefix are reported as manual rather than guessed at.
    """
    def line_repl(line_m: re.Match[str]) -> str:
        provider = line_m["provider"]
        body = line_m["body"]
        # Group claimed pieces by prefix.
        by_prefix: dict[str, list[re.Match[str]]] = {}
        for piece in _RANGE_PIECE_RE.finditer(body):
            by_prefix.setdefault(piece["prefix"], []).append(piece)

        new_body = body
        for prefix, pieces in by_prefix.items():
            existing = _existing_ids_for_prefix(provider, prefix)
            if not existing:
                continue
            highest_actual = max(existing)
            range_pieces = [p for p in pieces if p["hi"]]
            if len(pieces) == 1 and range_pieces:
                p = range_pieces[0]
                if int(p["hi"]) != highest_actual:
                    old = p.group(0)
                    new = f"{prefix}-{p['lo']}{p['sep']}{highest_actual:0{len(p['hi'])}d}"
                    new_body = new_body.replace(old, new, 1)
                    ch.changes.append(
                        ("README.md", f"{prefix}-{p['hi']} -> {prefix}-{highest_actual:03d} (arch range, {provider})")
                    )
            else:
                # Multiple pieces / singles for one prefix: only flag when
                # the highest claimed differs from reality.
                highest_claimed = max(int(p["hi"] or p["lo"]) for p in pieces)
                if highest_claimed != highest_actual:
                    ch.manual.append(
                        f"README.md architecture line for {provider}/{prefix}: claims highest "
                        f"{prefix}-{highest_claimed:03d}, registry has {prefix}-{highest_actual:03d} "
                        f"(complex body, fix by hand)"
                    )
        if new_body == body:
            return line_m.group(0)
        return line_m["indent"] + provider + line_m["mid"] + new_body

    return _RANGE_LINE_RE.sub(line_repl, text)


def _rewrite_comparison_rows(text: str, ch: Changer) -> str:
    rel = "docs/comparison.md"
    for row_name, slug in _COMPARISON_ROWS.items():
        actual = _count_rules_in(slug)
        pat = re.compile(rf"(\|\s*{re.escape(row_name)}\s*\|\s*Yes\s*\()(\d+)(\s+rules?)")
        m = pat.search(text)
        if not m or int(m.group(2)) == actual:
            continue
        ch.changes.append((rel, f"{m.group(2)} -> {actual} (comparison row: {row_name})"))
        text = text[:m.start()] + m.group(1) + str(actual) + m.group(3) + text[m.end():]
    return text


def _rewrite_mcp_count(text: str, ch: Changer) -> str:
    try:
        from pipeline_check.mcp_server.tools import TOOL_SPECS
    except Exception:
        return text
    expected = len(TOOL_SPECS)
    pat = re.compile(r"(\b)(\d+)(\s+tools advertised)")
    m = pat.search(text)
    if m and int(m.group(2)) != expected:
        ch.changes.append(("README.md", f"{m.group(2)} -> {expected} (MCP tools advertised)"))
        text = text[:m.start()] + m.group(1) + str(expected) + m.group(3) + text[m.end():]
    return text


# ──────────────────────────────────────────────────────────────────
# Driver
# ──────────────────────────────────────────────────────────────────


def sync(write: bool) -> Changer:
    ch = Changer()
    edited: dict[str, str] = {}

    for rel in _DOCS_WITH_CLAIMS:
        p = _REPO / rel
        if not p.is_file():
            continue
        text = original = p.read_text(encoding="utf-8")
        text = _rewrite_aggregate(text, rel, ch)
        if rel == "docs/index.md":
            text = _rewrite_index_stat_tiles(text, rel, ch)
        if rel == "README.md":
            text = _rewrite_readme_provider_table(text, ch)
            text = _rewrite_readme_aws_arch_line(text, ch)
            text = _rewrite_readme_arch_ranges(text, ch)
            text = _rewrite_mcp_count(text, ch)
        if text != original:
            edited[rel] = text

    comparison = _REPO / "docs" / "comparison.md"
    if comparison.is_file():
        text = original = comparison.read_text(encoding="utf-8")
        text = _rewrite_comparison_rows(text, ch)
        if text != original:
            edited["docs/comparison.md"] = text

    if write:
        for rel, text in edited.items():
            (_REPO / rel).write_text(text, encoding="utf-8")
    return ch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true",
        help="Report stale claims and exit non-zero; write nothing.",
    )
    args = parser.parse_args(argv)

    ch = sync(write=not args.check)

    if ch.changes:
        verb = "stale" if args.check else "updated"
        print(f"{len(ch.changes)} doc claim(s) {verb}:")
        for rel, desc in ch.changes:
            print(f"  {rel}: {desc}")
    if ch.manual:
        print("\nManual fixes still required (not auto-rewritten):")
        for note in ch.manual:
            print(f"  {note}")

    if args.check and (ch.changes or ch.manual):
        print("\nDoc claims are stale. Run: python scripts/sync_doc_claims.py")
        return 1
    if ch.manual:
        # Write mode still flags un-fixable drift loudly so it isn't
        # mistaken for "everything is in sync now".
        return 1
    if not args.check and not ch.changes:
        print("Doc claims already in sync; nothing to write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
