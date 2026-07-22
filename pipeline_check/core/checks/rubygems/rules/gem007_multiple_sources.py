"""GEM-007. Multiple top-level Gemfile sources without per-gem scoping."""
from __future__ import annotations

from urllib.parse import urlparse

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GemFile

_PUBLIC_RUBYGEMS_HOSTS = frozenset({"rubygems.org", "www.rubygems.org"})


def _is_public_rubygems(url: str) -> bool:
    """Return True when *url* is the canonical public rubygems.org host."""
    host = urlparse(url.strip()).netloc.lower()
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    return host in _PUBLIC_RUBYGEMS_HOSTS

RULE = Rule(
    id="GEM-007",
    title="Gemfile declares multiple top-level sources without scoping",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG",),
    cwe=("CWE-829",),
    recommendation=(
        "Replace the second top-level ``source`` with a scoped "
        "block: ``source \"https://gems.corp/private\" do … "
        "end``. Bundler 1.13+ warns on multiple top-level "
        "sources because the gem resolver can't tell which "
        "source a given name should come from — and an attacker "
        "publishing the same private gem name on rubygems.org "
        "first wins the lookup (the classic dependency-confusion "
        "vector). Pin private gems explicitly to the private "
        "source via a scoped block and leave only "
        "rubygems.org as the top-level default."
    ),
    docs_note=(
        "Fires when the Gemfile has two or more top-level "
        "``source \"...\"`` declarations and at least one is "
        "not the public rubygems.org. Scoped ``source ... do "
        "… end`` blocks are not counted toward the top-level "
        "total. Companion to NUGET-007 (packageSourceMapping "
        "missing) and NPM-009 (scope-without-registry)."
    ),
    known_fp=(
        "Legacy Gemfiles that have intentionally documented "
        "the dependency-confusion risk and accepted it (rare). "
        "Suppress at the Gemfile level with a one-line "
        "rationale.",
    ),
    incident_refs=(
        "Bundler's own gem-source documentation walks through "
        "the dependency-confusion scenario in detail: a private "
        "gem name registered first by an attacker on the public "
        "rubygems.org will resolve before the private mirror "
        "when both sources are top-level.",
    ),
    exploit_example=(
        "# Vulnerable: two top-level sources, no scoping.\n"
        "source \"https://rubygems.org\"\n"
        "source \"https://gems.corp/private\"\n"
        "gem \"internal-tool\", \"1.0.0\"\n"
        "# Risk: if an attacker registers ``internal-tool`` on\n"
        "# rubygems.org first, Bundler may resolve it from\n"
        "# there instead of the private mirror.\n"
        "\n"
        "# Safe: scoped block.\n"
        "source \"https://rubygems.org\"\n"
        "source \"https://gems.corp/private\" do\n"
        "  gem \"internal-tool\", \"1.0.0\"\n"
        "end"
    ),
)


def check(pom: GemFile) -> Finding:
    top_level = [s for s in pom.sources if s.is_top_level]
    non_public = [s for s in top_level if not _is_public_rubygems(s.url)]
    # The dependency-confusion split needs 2+ top-level sources AND at
    # least one non-public source (a private mirror the resolver can't
    # unambiguously prefer). Two identical rubygems.org declarations are
    # redundant, not a confusion vector.
    if len(top_level) <= 1 or not non_public:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Gemfile declares at most one top-level source, or every "
                "top-level source is the public rubygems.org."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"Gemfile declares {len(top_level)} top-level sources "
            f"without scoping: "
            f"{', '.join(s.url for s in top_level[:3])}"
            f"{'…' if len(top_level) > 3 else ''}. Bundler can't "
            f"unambiguously resolve a gem name across multiple "
            f"top-level sources; the dep-confusion attacker wins."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
