"""Lock doc claims against the live code.

Numerical claims in `README.md` and `docs/index.md` ("12 providers",
"13 compliance standards", "68 autofixers", "8 attack chains",
"370+ checks") are easy to lie about and easy to forget when adding
a new provider, fixer, or standard. This test scans the doc set for
those claims and asserts each one matches what the registries
actually expose.

Numbers are derived from code, not hardcoded. Adding a new provider
auto-bumps the expected value. The test fails iff a doc says
something the registries disagree with.

Maintenance contract
--------------------
- Add a provider / standard / autofixer / chain rule, no test edits
  needed; this test fails until you bump the doc claim.
- Add a new doc file that makes a numerical claim, append the path
  to ``DOCS_WITH_CLAIMS`` below.
- Reword a claim from digits to spelled-out form ("12" to "twelve"):
  the digit-form regexes won't catch it. That's intentional. Prose
  variants stay a manual concern; structural claims are the
  high-drift risk this test guards against.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from pipeline_check.core.autofix import _FIXERS as _AUTOFIXERS
from pipeline_check.core.providers import available as _providers_available
from pipeline_check.core.standards import available as _standards_available

REPO = Path(__file__).resolve().parent.parent

# Files that are expected to carry numerical claims about coverage.
# Add new ones here as the doc set grows.
DOCS_WITH_CLAIMS = [
    REPO / "README.md",
    REPO / "docs" / "index.md",
]


# ──────────────────────────────────────────────────────────────────
# Live counts from the code
# ──────────────────────────────────────────────────────────────────


def _count_providers() -> int:
    return len(_providers_available())


def _count_standards() -> int:
    return len(_standards_available())


def _count_autofixers() -> int:
    return len(_AUTOFIXERS)


def _count_attack_chains() -> int:
    chains_dir = REPO / "pipeline_check" / "core" / "chains" / "rules"
    if not chains_dir.is_dir():
        return 0
    return sum(
        1 for p in chains_dir.iterdir()
        if p.suffix == ".py"
           and p.name != "__init__.py"
           and not p.name.startswith("_")
    )


def _count_rule_files() -> int:
    """Count one-rule-per-file modules under every provider's rules/ dir."""
    checks_dir = REPO / "pipeline_check" / "core" / "checks"
    n = 0
    for prov_dir in checks_dir.iterdir():
        if not prov_dir.is_dir():
            continue
        rules_dir = prov_dir / "rules"
        if not rules_dir.is_dir():
            continue
        for f in rules_dir.iterdir():
            if (
                f.suffix == ".py"
                and f.name != "__init__.py"
                and not f.name.startswith("_")
            ):
                n += 1
    return n


def _count_total_checks() -> int:
    """Best-effort total of every check ID a full scan can emit.

    Equals: rule-pattern files (workflow providers + cloudbuild +
    dockerfile + kubernetes) + the AWS / Terraform / CloudFormation
    catalog (which carries its checks as class methods, not files).
    The AWS / TF / CFN tally is taken from the README provider table
    so the source-of-truth is the same place a reader would compute
    it from.
    """
    return _count_rule_files() + _AWSLIKE_TOTAL


# AWS, Terraform, CloudFormation per the README provider table.
# AWS = 71, CFN ≈ 63 (Terraform parity reuses AWS rules so doesn't
# add to the unique-ID count). Bump these when README:54-56 changes.
_AWSLIKE_TOTAL = 71 + 63


# ──────────────────────────────────────────────────────────────────
# Claim parsers
# ──────────────────────────────────────────────────────────────────

# ``**12 providers**``, ``12 providers``, ``12 Providers``, etc.
# Case-insensitive so the stat-block label ("Providers") matches after
# HTML normalization strips the surrounding tags.
_PROVIDER_CLAIM = re.compile(
    r"\b(\d+)\s+(?:CI/CD\s+)?providers?\b", re.IGNORECASE
)
_STANDARD_CLAIM = re.compile(
    r"\b(\d+)\s+(?:compliance\s+)?(?:standards?|frameworks?)\b",
    re.IGNORECASE,
)
_AUTOFIXER_CLAIM = re.compile(
    r"\b(\d+)\s+(?:autofixer|fixer)s?\b", re.IGNORECASE
)
_CHAIN_CLAIM = re.compile(r"\b(\d+)\s+attack\s+chains?\b", re.IGNORECASE)
# "430+ checks". The trailing ``+`` is mandatory so per-provider rows
# in the README provider table ("71 checks") aren't read as total-
# catalog claims. Total-catalog claims always carry the ``+``.
_CHECK_CLAIM = re.compile(r"\b(\d+)\+\s+checks?\b", re.IGNORECASE)


_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _normalise(text: str) -> str:
    """Strip HTML tags so the digit-then-noun regexes match across
    template structures like ``<div>12</div><div>Providers</div>``."""
    # Replace tags with a single space so adjacent tokens don't merge.
    return _HTML_TAG_RE.sub(" ", text)


def _findall(pattern: re.Pattern, text: str) -> list[int]:
    return [int(m) for m in pattern.findall(_normalise(text))]


# ──────────────────────────────────────────────────────────────────
# Tests. One per claim type, parameterized over the doc set.
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("doc", DOCS_WITH_CLAIMS)
def test_provider_count_matches_registry(doc: Path):
    expected = _count_providers()
    text = doc.read_text(encoding="utf-8")
    found = _findall(_PROVIDER_CLAIM, text)
    assert found, (
        f"{doc.relative_to(REPO)}: no '<N> providers' claim found. "
        f"At least one is expected so this test can guard the count."
    )
    drift = [n for n in found if n != expected]
    assert not drift, (
        f"{doc.relative_to(REPO)}: provider-count drift, claim(s) "
        f"{drift}, registry has {expected}. Update the doc or check "
        f"pipeline_check.core.providers."
    )


@pytest.mark.parametrize("doc", DOCS_WITH_CLAIMS)
def test_standards_count_matches_registry(doc: Path):
    expected = _count_standards()
    text = doc.read_text(encoding="utf-8")
    found = _findall(_STANDARD_CLAIM, text)
    if not found:
        return  # not every doc needs a standards claim
    # The phrasing "OWASP Top 10 plus twelve compliance frameworks"
    # in prose treats OWASP as separate from "the other twelve", so
    # we accept either the full count or count - 1.
    drift = [n for n in found if n not in (expected, expected - 1)]
    assert not drift, (
        f"{doc.relative_to(REPO)}: standards-count drift, claim(s) "
        f"{drift}, registry has {expected} (also accepts "
        f"{expected - 1} for the 'plus N other frameworks' prose)."
    )


@pytest.mark.parametrize("doc", DOCS_WITH_CLAIMS)
def test_autofixer_count_matches_registry(doc: Path):
    expected = _count_autofixers()
    text = doc.read_text(encoding="utf-8")
    found = _findall(_AUTOFIXER_CLAIM, text)
    if not found:
        return
    drift = [n for n in found if n != expected]
    assert not drift, (
        f"{doc.relative_to(REPO)}: autofixer-count drift, claim(s) "
        f"{drift}, _FIXERS has {expected} entries. Bump the doc or "
        f"add the missing register() decorator in core/autofix.py."
    )


@pytest.mark.parametrize("doc", DOCS_WITH_CLAIMS)
def test_attack_chain_count_matches_registry(doc: Path):
    expected = _count_attack_chains()
    text = doc.read_text(encoding="utf-8")
    found = _findall(_CHAIN_CLAIM, text)
    if not found:
        return
    drift = [n for n in found if n != expected]
    assert not drift, (
        f"{doc.relative_to(REPO)}: attack-chain-count drift, claim(s) "
        f"{drift}, chains/rules/ has {expected} files. Bump the doc "
        f"or add the missing rule module."
    )


@pytest.mark.parametrize("doc", DOCS_WITH_CLAIMS)
def test_total_check_floor(doc: Path):
    """Doc claims like '370+ checks' must be reasonable approximations
    of the actual catalog size: at most equal, at most ~50 below."""
    text = doc.read_text(encoding="utf-8")
    found = _findall(_CHECK_CLAIM, text)
    if not found:
        return
    actual = _count_total_checks()
    for n in found:
        # Claim is a floor: actual must be >= n (else doc lies).
        assert n <= actual, (
            f"{doc.relative_to(REPO)}: claims '{n}+ checks'; actual "
            f"catalog is {actual} (rule files + AWS-like). The doc "
            f"is overstating coverage."
        )
        # Claim should be a sensible approximation: not absurdly low.
        # Catch the case where the catalog grew significantly but
        # the doc still says an old, much-smaller number.
        assert n >= actual - 50, (
            f"{doc.relative_to(REPO)}: claims '{n}+ checks' but the "
            f"catalog has grown to {actual}. Bump the claim to a "
            f"current floor (rounded down to a multiple of 10)."
        )


# ──────────────────────────────────────────────────────────────────
# Sanity gates. Protects against an empty-registry regression.
# ──────────────────────────────────────────────────────────────────


def test_registries_are_non_empty():
    assert _count_providers() > 0
    assert _count_standards() > 0
    assert _count_autofixers() > 0
    assert _count_attack_chains() > 0
    assert _count_rule_files() > 0


def test_provider_registry_count_lines_up_with_known_floor():
    """If a contributor accidentally drops a register() call from
    providers/__init__.py, the registry shrinks. This guards against
    a silent regression by fixing a known minimum."""
    assert _count_providers() >= 12
