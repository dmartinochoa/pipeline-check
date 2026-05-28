"""GOMOD-010. go.mod exclude directive masks an upstream version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-010",
    title="go.mod exclude directive masks an upstream version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Audit every ``exclude`` directive and remove the ones "
        "that aren't load-bearing. ``exclude <path> <version>`` "
        "tells Go's module graph resolver to skip the named "
        "version — useful for blocking a known-broken release "
        "from a transitive resolution, but often left over from "
        "a long-ago dependency conflict that's since been "
        "patched upstream.\n\n"
        "The two failure modes:\n\n"
        "1. The excluded version is no longer relevant (upstream "
        "fixed the issue in a later release). Remove the "
        "exclude.\n"
        "2. The excluded version carries a security advisory "
        "(``exclude`` hides it from the resolver, but a "
        "deliberate ``require`` at the same version still "
        "pulls it). Replace the exclude with an explicit "
        "patched-version require so future audits see the "
        "intent.\n\n"
        "Pair every kept exclude with a comment naming the "
        "incident or upstream issue that justified it. "
        "Excludes without rationale are a code-rot signal."
    ),
    docs_note=(
        "Fires on any ``exclude`` directive in go.mod. The rule "
        "is informational-leaning MEDIUM: excludes are not "
        "themselves a vulnerability, they're a posture / hygiene "
        "signal. Long-lived excludes without comments often "
        "outlive the upstream issue that prompted them, and "
        "their continued presence in the manifest creates "
        "audit-trail noise around the dependency graph.\n\n"
        "Distinct from GOMOD-006 (known-compromised version) "
        "and GOMOD-004 (+incompatible version): those rules "
        "audit *what's used*, this one audits *what's "
        "deliberately blocked* and surfaces the staleness "
        "class."
    ),
    known_fp=(
        "Excludes pinned to a specific known-broken upstream "
        "release that's still in the module graph's "
        "transitive set are legitimate and load-bearing. The "
        "rule fires anyway because the cleanup decision "
        "requires context the manifest doesn't carry. Suppress "
        "per directive with a one-line rationale naming the "
        "upstream issue.",
    ),
    incident_refs=(
        "Pattern in long-lived Go monorepos: an exclude from "
        "2019 blocks a then-broken patch release; the upstream "
        "has since rolled forward and the block is irrelevant, "
        "but no audit cycle has touched the directive. Cleanup "
        "of stale excludes during dep-update sprints is a "
        "common posture-hygiene exercise.",
    ),
    exploit_example=(
        "// Vulnerable: stale exclude with no rationale.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/foo/bar v1.5.0\n"
        "exclude github.com/foo/bar v1.2.0\n"
        "\n"
        "// Risk: the exclude blocks v1.2.0 from the transitive\n"
        "// graph. If the original reason was a known issue\n"
        "// fixed in v1.3.0 (already a year ago), the exclude\n"
        "// is dead weight; if the original reason was a\n"
        "// security advisory still in scope, the exclude\n"
        "// alone doesn't prevent a direct require pinning the\n"
        "// affected version, so the protection is partial.\n"
        "\n"
        "// Safe: remove if no longer needed, or document.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/foo/bar v1.5.0\n"
        "// Excluded because v1.2.0 has GHSA-xxxx (cite link).\n"
        "exclude github.com/foo/bar v1.2.0"
    ),
)


def check(pom: GoModFile) -> Finding:
    if not pom.excludes:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="go.mod declares no exclude directives.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders = [
        f"{exc.path} {exc.version}" for exc in pom.excludes
    ]
    locations = [
        Location(
            path=pom.path,
            start_line=exc.line_no, end_line=exc.line_no,
        )
        for exc in pom.excludes
    ]
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"{len(offenders)} exclude directive(s) in go.mod: "
            f"{', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}. Audit each "
            f"one — stale excludes are dead weight; "
            f"advisory-driven excludes should be paired with a "
            f"patched-version require for explicit intent."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
