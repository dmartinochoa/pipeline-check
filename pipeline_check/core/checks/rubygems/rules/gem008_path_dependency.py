"""GEM-008. Gemfile ``gem`` declared with a ``path:`` source."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-008",
    title="Gemfile gem declared with a path: source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Replace the ``path:`` source with a published, "
        "version-pinned dependency. A ``path:`` entry installs "
        "the gem from a local directory on the build runner, "
        "which:\n\n"
        "1. bypasses the registry-side audit trail entirely "
        "(no version, no checksum, no advisory check),\n"
        "2. is reproducible only if the local directory layout "
        "is reproducible (and CI runners rarely have one),\n"
        "3. can be subverted by anything that can write to that "
        "directory before ``bundle install`` runs (cache "
        "poisoning, parallel job, ``actions/cache`` race).\n\n"
        "If the dependency is genuinely a local development "
        "convenience, gate it behind ``group :development`` so "
        "it never runs in CI / production. If it has to ship, "
        "publish it as a real gem and pin the version."
    ),
    docs_note=(
        "Fires on any ``gem \"x\", path: \"...\"`` entry that "
        "is not scoped to ``group :development`` / ``group "
        ":test`` only. Development-group-only path entries pass "
        "since they're explicitly excluded from production "
        "bundles. Mirrors CARGO-004 (path Cargo dep) and "
        "GOMOD-002 (local replace directive)."
    ),
    known_fp=(
        "Development-group path entries are explicitly allowed. "
        "If a path entry legitimately needs to ship to "
        "production (rare — usually means the dependency "
        "should be properly published as a real gem) suppress "
        "with a one-line rationale.",
    ),
    incident_refs=(
        "Cache-poisoning vector: an attacker who can write to "
        "the ``path:`` directory (parallel job sharing a "
        "workspace, a compromised CI cache, a writable "
        "``actions/cache`` key) substitutes a malicious "
        "version of the local gem and the next ``bundle "
        "install`` ingests it.",
    ),
    exploit_example=(
        "# Vulnerable: path source in production scope.\n"
        "source \"https://rubygems.org\"\n"
        "gem \"internal-helper\", path: \"../internal-helper\"\n"
        "\n"
        "# Risk: nothing about ``../internal-helper`` is\n"
        "# auditable from the manifest. Whoever writes there\n"
        "# wins.\n"
        "\n"
        "# Safe: dev-only convenience.\n"
        "group :development do\n"
        "  gem \"internal-helper\", path: \"../internal-helper\"\n"
        "end\n"
        "# Or: publish as a real gem.\n"
        "gem \"internal-helper\", \"1.0.0\""
    ),
)


_DEV_GROUPS: frozenset[str] = frozenset({"development", "test"})


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.is_path:
            continue
        # Dev / test-only path entries are explicitly allowed.
        if dep.groups and all(g in _DEV_GROUPS for g in dep.groups):
            continue
        offenders.append(dep.name)
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No production-scope gem uses a path: source."
        )
    else:
        rendered = ", ".join(offenders[:5])
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} gem(s) declared with a path: "
            f"source in production scope: {rendered}{suffix}. "
            f"Move to ``group :development``, publish as a real "
            f"gem, or pin to a registry version."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
