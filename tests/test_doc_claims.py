"""Lock doc claims against the live code.

Numerical claims in `README.md` and `docs/index.md` ("13 providers",
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


_CHECK_ID_LITERAL = re.compile(r'check_id="([A-Z]+-\d+)"')


def _count_class_based_check_ids(provider: str) -> int:
    """Count distinct ``check_id="..."`` literals under one provider's
    class-based modules (Terraform / CloudFormation).

    Skips ``rules/`` subpackages, which the file-counter already covers,
    and skips dunder / private modules.
    """
    prov_dir = REPO / "pipeline_check" / "core" / "checks" / provider
    if not prov_dir.is_dir():
        return 0
    ids: set[str] = set()
    for f in prov_dir.rglob("*.py"):
        if "rules" in f.parts:
            continue
        if f.name.startswith("_") or f.name == "__init__.py":
            continue
        ids.update(_CHECK_ID_LITERAL.findall(f.read_text(encoding="utf-8")))
    return len(ids)


def _count_total_checks() -> int:
    """Best-effort total of every check ID a full scan can emit.

    Equals: rule-pattern files (one per check, found under every
    provider's ``rules/`` subpackage, AWS included) + Terraform's
    class-based check IDs + CloudFormation's class-based check IDs.
    Both class-based packs reuse AWS IDs for parity, but emit findings
    on Terraform plans / CFN templates respectively, so they're
    counted toward the realistic catalog floor a doc claim is
    measuring.
    """
    return (
        _count_rule_files()
        + _count_class_based_check_ids("terraform")
        + _count_class_based_check_ids("cloudformation")
    )


# ──────────────────────────────────────────────────────────────────
# Claim parsers
# ──────────────────────────────────────────────────────────────────

# ``**13 providers**``, ``13 providers``, ``13 Providers``, etc.
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
        # the doc still says an old, much-smaller number. Tightened
        # from 50 to 20 once ``_count_total_checks`` switched to a
        # filesystem-derived count: the prior tolerance was padding
        # for a hand-maintained ``_AWSLIKE_TOTAL`` literal that no
        # longer exists.
        assert n >= actual - 20, (
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
    assert _count_providers() >= 13


# ──────────────────────────────────────────────────────────────────
# Per-provider drift guards.
#
# The aggregate counts above (providers, standards, autofixers, total
# checks) catch top-level drift. The two tests below catch the harder
# case: the contributor adds a single new rule under one provider's
# pack, which doesn't move the aggregate enough to register, but the
# per-provider claim ("GitHub Actions: 50 checks", "GHA-001 .. GHA-047")
# silently goes stale.
# ──────────────────────────────────────────────────────────────────


def _count_rules_in(provider: str) -> int:
    """Count rule-module files under a single provider's ``rules/`` dir."""
    rules_dir = REPO / "pipeline_check" / "core" / "checks" / provider / "rules"
    if not rules_dir.is_dir():
        return 0
    return sum(
        1 for f in rules_dir.iterdir()
        if f.suffix == ".py"
        and f.name != "__init__.py"
        and not f.name.startswith("_")
    )


def _existing_ids_for_prefix(provider: str, prefix: str) -> set[int]:
    """Return numeric suffixes of every ``<prefix><N>_*.py`` rule file
    in the provider's ``rules/`` dir. Empty set when nothing matches."""
    rules_dir = REPO / "pipeline_check" / "core" / "checks" / provider / "rules"
    if not rules_dir.is_dir():
        return set()
    pat = re.compile(rf"^{prefix.lower()}(\d+)_")
    return {int(m.group(1)) for f in rules_dir.iterdir() if (m := pat.match(f.name))}


# Match every <a class="pg-provider"> tile in docs/index.md.
# href="providers/<NAME>/" identifies the provider; the count <span>
# now carries a Jinja token like ``{{ providers.aws.checks }}`` that
# the ``hooks/mkdocs_provider_stats.py`` build-time hook resolves
# against the live rule registry. The test below checks that the
# token wiring is intact and that the hook has a label for every
# slug referenced on the home page.
_PROVIDER_TILE_RE = re.compile(
    r'href="providers/(?P<name>[^/"]+)/"'
    r'.*?<span class="pg-provider__count">(?P<count>[^<]+)</span>',
    re.DOTALL,
)
_PROVIDER_TOKEN_RE = re.compile(
    r"\{\{\s*providers\.(?P<slug>[a-z0-9_]+)\.checks\s*\}\}"
)


def test_index_per_provider_tiles_use_hook_tokens():
    """Every <span class="pg-provider__count"> tile on the home page
    must carry a ``{{ providers.<slug>.checks }}`` token and the hook
    must have a non-empty label for that slug.

    Before this test existed, the tile counts were hand-edited literals
    (``50 checks``, ``aws-parity``, ``renders + 40 K8S-* rules + 10
    HELM-*`` — four different formats!) and drifted whenever a rule
    landed. The hook-token contract removes the drift class entirely:
    counts come from
    ``pipeline_check/core/checks/<provider>/rules/`` at build time.

    This test guards the wiring: that every tile uses a token, that
    the tile's ``href="providers/<slug>"`` matches the token's slug,
    and that the hook resolves the slug to a non-empty label.
    """
    # Import the hook from the absolute hooks/ path. The directory
    # isn't on sys.path by default; resolve it relative to REPO so
    # this works in CI / tox / IDE runners alike.
    import sys
    sys.path.insert(0, str(REPO / "hooks"))
    try:
        from mkdocs_provider_stats import _INDEX as _PROVIDER_INDEX
    finally:
        sys.path.pop(0)

    text = (REPO / "docs" / "index.md").read_text(encoding="utf-8")
    tiles = _PROVIDER_TILE_RE.findall(text)
    assert tiles, (
        "no provider tiles found in docs/index.md, _PROVIDER_TILE_RE "
        "is likely out of sync with the doc structure"
    )

    drift: list[str] = []
    for href_name, count_text in tiles:
        m = _PROVIDER_TOKEN_RE.search(count_text)
        if not m:
            drift.append(
                f"docs/index.md tile for providers/{href_name}/ has "
                f"no ``{{{{ providers.<slug>.checks }}}}`` token; "
                f"hand-edited literals defeat the drift guard"
            )
            continue
        token_slug = m.group("slug")
        if token_slug != href_name:
            drift.append(
                f"docs/index.md tile href=providers/{href_name}/ uses "
                f"a mismatched token providers.{token_slug}.checks"
            )
            continue
        label = _PROVIDER_INDEX.get(token_slug, {}).get("checks", "")
        if not label:
            drift.append(
                f"hooks/mkdocs_provider_stats.py has no checks-label "
                f"for slug '{token_slug}' referenced by "
                f"docs/index.md; either the provider doesn't exist or "
                f"the hook's _CLASS_BASED_LABELS / _build_index needs "
                f"a new entry"
            )

    assert not drift, "docs/index.md tile drift:\n  " + "\n  ".join(drift)


# Match each ``├── <provider>/rules/  # <body>`` line in the README
# architecture block. The body holds rule-range claims like
# ``GHA-001 .. GHA-047 + TAINT-001..003``.
_RANGE_LINE_RE = re.compile(
    r"^\s*├──\s*(?P<provider>\w+)/rules/\s*#\s*(?P<body>.+)$",
    re.MULTILINE,
)
# Pull every ``PREFIX-NNN`` (single) or ``PREFIX-NNN..MMM`` (range) from
# a body. Range form supports both ``PFX-NNN .. PFX-MMM`` and the more
# compact ``PFX-NNN..MMM``. The prefix must begin with a letter and may
# contain digits (handles ``K8S``); the leading ``\b`` stops the engine
# from matching ``S-001`` inside ``K8S-001`` as a separate claim.
_RANGE_PIECE_RE = re.compile(
    r"\b(?P<prefix>[A-Z][A-Z0-9]*)-(?P<lo>\d+)"
    r"(?:\s*\.\.\s*(?:(?P=prefix)-)?(?P<hi>\d+))?"
)
# Match the AWS line specifically: ``# 71 rule-based checks (...)``.
_AWS_COUNT_LINE_RE = re.compile(
    r"├──\s*aws/rules/\s*#\s*(\d+)\s+rule-based\s+checks?", re.IGNORECASE
)


def test_readme_architecture_rule_ranges_match_registry():
    """The architecture block in README.md lists each rule pack's ID
    range (e.g. ``GHA-001 .. GHA-047 + TAINT-001..003``). For each
    claimed range, the high end must match the highest-numbered rule
    file in that provider's ``rules/`` directory; for each claimed
    single ID (``TAINT-004 / TAINT-008``), the file must exist.

    Catches: contributor adds a rule but forgets to bump the README
    range; contributor renames a rule out of one provider into
    another; contributor adds a TAINT/ATTEST/etc. cross-pack rule
    that the README doesn't acknowledge.
    """
    text = (REPO / "README.md").read_text(encoding="utf-8")

    # Aws line uses a different shape (count, not range). Verify it
    # explicitly so the architecture block is fully covered.
    aws_match = _AWS_COUNT_LINE_RE.search(text)
    assert aws_match, (
        "README.md architecture block missing the 'aws/rules/  # N "
        "rule-based checks' line, or the format changed"
    )
    claimed_aws = int(aws_match.group(1))
    actual_aws = _count_rules_in("aws")
    assert claimed_aws == actual_aws, (
        f"README.md aws/rules/ line claims {claimed_aws} rule-based "
        f"checks, registry has {actual_aws}"
    )

    matches = list(_RANGE_LINE_RE.finditer(text))
    assert matches, (
        "README.md architecture block has no '├── <provider>/rules/' "
        "lines, _RANGE_LINE_RE likely out of sync with the doc"
    )

    drift: list[str] = []
    for line_match in matches:
        provider = line_match["provider"]
        body = line_match["body"]
        # Group claimed pieces by prefix so we can compare highs and
        # validate any singles (hi is None on a single ``PFX-NNN``).
        by_prefix: dict[str, list[tuple[int, int | None]]] = {}
        for piece in _RANGE_PIECE_RE.finditer(body):
            prefix = piece["prefix"]
            lo = int(piece["lo"])
            hi = int(piece["hi"]) if piece["hi"] else None
            by_prefix.setdefault(prefix, []).append((lo, hi))

        for prefix, claims in by_prefix.items():
            existing = _existing_ids_for_prefix(provider, prefix)
            if not existing:
                drift.append(
                    f"{provider}/rules/: README claims {prefix}-* but "
                    f"no {prefix.lower()}*_*.py file found"
                )
                continue

            # Highest claimed (range end or single).
            highest_claimed = max(hi if hi is not None else lo for lo, hi in claims)
            highest_actual = max(existing)
            if highest_claimed != highest_actual:
                drift.append(
                    f"{provider}/rules/ {prefix}: README claims highest "
                    f"is {prefix}-{highest_claimed:03d}, registry has "
                    f"{prefix}-{highest_actual:03d}"
                )

            # Each single-ID claim (no range hi) must exist.
            for lo, hi in claims:
                if hi is None and lo not in existing:
                    drift.append(
                        f"{provider}/rules/ {prefix}: README claims "
                        f"{prefix}-{lo:03d} but no "
                        f"{prefix.lower()}{lo:03d}_*.py exists"
                    )

    assert not drift, (
        "README.md architecture block drift:\n  " + "\n  ".join(drift)
    )


# ──────────────────────────────────────────────────────────────────
# Comparison-page per-row drift guard.
#
# ``docs/comparison.md`` has a feature matrix whose Pipeline-Check
# column carries cell counts like ``Yes (53 rules)`` or
# ``Yes (43 + 10)``. Those numbers are not auto-derived; before this
# test, every per-cell count quietly went stale as new rules landed.
# ──────────────────────────────────────────────────────────────────

# Row name → provider slug. The row name is the first non-empty cell
# of the table row (the capability label); the slug is the provider
# whose rule-file count the cell's first integer must match.
_COMPARISON_ROWS: dict[str, str] = {
    "GitHub Actions": "github",
    "GitLab CI": "gitlab",
    "Jenkins (Declarative + Scripted)": "jenkins",
    "CircleCI": "circleci",
    "Azure DevOps": "azure",
    "Bitbucket Pipelines": "bitbucket",
    "Google Cloud Build": "cloudbuild",
    "Buildkite": "buildkite",
    "Drone CI": "drone",
    "Tekton": "tekton",
    "Argo Workflows": "argo",
    "Kubernetes manifests": "kubernetes",
    "Dockerfile": "dockerfile",
    "Live AWS account scan": "aws",
}


def test_comparison_per_row_rule_counts_match_registry():
    """The per-row Pipeline-Check cell in ``docs/comparison.md``
    declares a rule count like ``Yes (53 rules)``. Each declared count
    must match the rule-file count in the corresponding provider's
    ``rules/`` directory.

    Catches drift the moment a new rule lands and the matrix isn't
    bumped.
    """
    text = (REPO / "docs" / "comparison.md").read_text(encoding="utf-8")
    drift: list[str] = []

    for row_name, slug in _COMPARISON_ROWS.items():
        # Match the row's Pipeline-Check cell: the first ``Yes (...)``
        # after the row label. The label can contain regex metachars
        # (parens in "Jenkins (Declarative + Scripted)") so escape it.
        pat = re.compile(
            rf"\|\s*{re.escape(row_name)}\s*\|\s*Yes\s*\(([^)]+)\)",
        )
        m = pat.search(text)
        if not m:
            drift.append(
                f"comparison.md: row '{row_name}' missing or its "
                f"Pipeline-Check cell isn't 'Yes (...)'"
            )
            continue
        cell = m.group(1)
        # First integer in the cell is the rule count.
        num_match = re.search(r"\b(\d+)\b", cell)
        if not num_match:
            drift.append(
                f"comparison.md: row '{row_name}' cell '{cell}' has "
                f"no integer rule count"
            )
            continue
        claimed = int(num_match.group(1))
        actual = _count_rules_in(slug)
        if claimed != actual:
            drift.append(
                f"comparison.md: row '{row_name}' claims {claimed} "
                f"rules, registry has {actual}"
            )

    # Helm row carries two numbers: ``Yes (43 + 10)`` — first is the
    # K8s pack reused via render, second is the chart-supply-chain
    # HELM-* pack. Verify both.
    helm_pat = re.compile(
        r"\|\s*Helm charts \(rendered \+ supply-chain\)\s*\|\s*Yes\s*\((\d+)\s*\+\s*(\d+)\)"
    )
    helm_m = helm_pat.search(text)
    if not helm_m:
        drift.append(
            "comparison.md: Helm row missing or doesn't carry "
            "'Yes (N + M)' shape"
        )
    else:
        k8s_claimed = int(helm_m.group(1))
        helm_claimed = int(helm_m.group(2))
        k8s_actual = _count_rules_in("kubernetes")
        helm_actual = _count_rules_in("helm")
        if k8s_claimed != k8s_actual:
            drift.append(
                f"comparison.md: Helm row claims {k8s_claimed} K8S-* "
                f"rules, registry has {k8s_actual}"
            )
        if helm_claimed != helm_actual:
            drift.append(
                f"comparison.md: Helm row claims {helm_claimed} HELM-* "
                f"rules, registry has {helm_actual}"
            )

    # SCM row carries an explicit highest-ID claim: ``SCM-001..NNN``.
    scm_pat = re.compile(
        r"GitHub repo branch protection[^|]+\|\s*Yes\s*\((\d+),\s*`SCM-001\.\.0?(\d+)`\)"
    )
    scm_m = scm_pat.search(text)
    if not scm_m:
        drift.append(
            "comparison.md: SCM row missing or its 'Yes (N, `SCM-001..NNN`)' "
            "shape changed"
        )
    else:
        scm_count_claimed = int(scm_m.group(1))
        scm_high_claimed = int(scm_m.group(2))
        scm_count_actual = _count_rules_in("scm")
        scm_high_actual = max(_existing_ids_for_prefix("scm", "SCM"), default=0)
        if scm_count_claimed != scm_count_actual:
            drift.append(
                f"comparison.md: SCM row claims {scm_count_claimed} "
                f"rules, registry has {scm_count_actual}"
            )
        if scm_high_claimed != scm_high_actual:
            drift.append(
                f"comparison.md: SCM row claims SCM-001..{scm_high_claimed:03d}, "
                f"registry's highest is SCM-{scm_high_actual:03d}"
            )

    # OCI row carries 'Yes (N, incl. ATTEST-001..NNN ...)'. The N
    # is the combined OCI-* + ATTEST-* total; the ATTEST high
    # must match the highest ATTEST file.
    oci_pat = re.compile(
        r"OCI image manifests[^|]+\|\s*Yes\s*\((\d+),\s*incl\.\s*ATTEST-001\.\.0?(\d+)"
    )
    oci_m = oci_pat.search(text)
    if not oci_m:
        drift.append(
            "comparison.md: OCI row missing or its 'Yes (N, incl. "
            "ATTEST-001..NNN ...)' shape changed"
        )
    else:
        oci_total_claimed = int(oci_m.group(1))
        attest_high_claimed = int(oci_m.group(2))
        oci_total_actual = _count_rules_in("oci")
        attest_high_actual = max(
            _existing_ids_for_prefix("oci", "ATTEST"), default=0
        )
        if oci_total_claimed != oci_total_actual:
            drift.append(
                f"comparison.md: OCI row claims {oci_total_claimed} "
                f"rules, registry has {oci_total_actual}"
            )
        if attest_high_claimed != attest_high_actual:
            drift.append(
                f"comparison.md: OCI row claims ATTEST-001.."
                f"{attest_high_claimed:03d}, registry's highest is "
                f"ATTEST-{attest_high_actual:03d}"
            )

    assert not drift, "comparison.md drift:\n  " + "\n  ".join(drift)


# ──────────────────────────────────────────────────────────────────
# Severity-legend drift guard.
#
# The canonical CRITICAL / HIGH / MEDIUM / LOW / INFO definitions
# live in ``scripts/gen_standards_docs.py::_SEVERITY_GUIDE``. The full
# legend table was previously duplicated on every generated standards
# page (60+ lines × 14 pages). Now generated pages emit a one-line
# pointer to ``docs/standards/README.md#how-to-read-severity`` and the
# full table lives once in that README. This test catches the case
# where the constants change but the README is forgotten (or vice
# versa).
# ──────────────────────────────────────────────────────────────────


def test_severity_legend_in_readme_matches_constants():
    """The hand-maintained severity legend in
    ``docs/standards/README.md`` must contain the same definition rows
    as ``scripts/gen_standards_docs.py::_SEVERITY_GUIDE``.

    Compares each level's "meaning" and "examples" text (verbatim
    substring match), not the surrounding markdown chrome. If a level
    is renamed or its prose is rewritten in the generator script, the
    README must be updated to match, and vice versa.
    """
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        from gen_standards_docs import _SEVERITY_GUIDE  # type: ignore
    finally:
        sys.path.pop(0)

    readme = (REPO / "docs" / "standards" / "README.md").read_text(
        encoding="utf-8"
    )
    drift: list[str] = []
    for level, meaning, examples in _SEVERITY_GUIDE:
        # ``meaning`` and ``examples`` strings can contain backticks,
        # double quotes, commas, etc. Substring match is the cheapest
        # way to assert "this prose appears in the README" without
        # forcing line-by-line markdown equality (which would be
        # fragile against trailing whitespace and the like).
        if meaning not in readme:
            drift.append(
                f"docs/standards/README.md severity legend missing "
                f"the '{level}' meaning prose. Update the README to "
                f"match ``_SEVERITY_GUIDE`` in "
                f"scripts/gen_standards_docs.py."
            )
        if examples not in readme:
            drift.append(
                f"docs/standards/README.md severity legend missing "
                f"the '{level}' examples prose."
            )

    assert not drift, "severity-legend drift:\n  " + "\n  ".join(drift)
