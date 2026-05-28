"""GEM-001. Gemfile present without a sibling Gemfile.lock."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-001",
    title="Gemfile present without a sibling Gemfile.lock",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "Commit ``Gemfile.lock`` to the repository. Bundler "
        "resolves the dependency graph once at ``bundle install`` "
        "time and records the exact resolved versions for every "
        "transitive gem in the lockfile; every subsequent "
        "``bundle install`` reads from the lockfile, so every "
        "build (locally and in CI) installs the same gem "
        "versions. Without it, Bundler re-resolves the manifest "
        "on every run and is free to pick the latest matching "
        "patch under any floating spec (GEM-002).\n\n"
        "For libraries packaged as a ``.gemspec`` published to "
        "rubygems.org, the convention is to leave Gemfile.lock "
        "out of version control so downstream applications can "
        "deduplicate. This rule still fires on those, suppress "
        "per gem with a one-line rationale naming the "
        "gem-as-library posture. The default posture "
        "(Gemfile.lock committed) is correct for Rails / Sinatra "
        "/ Hanami apps, internal services, CLI utilities, and "
        "anything that runs ``bundle install`` in CI."
    ),
    docs_note=(
        "Fires when the Gemfile's directory has no "
        "``Gemfile.lock`` sibling. Libraries that legitimately "
        "publish without a lockfile need a per-file suppression "
        "with a one-line rationale naming the library posture."
    ),
    known_fp=(
        "Library gems published to rubygems.org intentionally "
        "omit Gemfile.lock from version control so downstream "
        "applications can deduplicate transitive deps. Suppress "
        "per gem with a one-line rationale.",
    ),
    incident_refs=(
        "Long-running pattern of Ruby applications that ignore "
        "Gemfile.lock in .gitignore (a habit imported from gem "
        "development). CI builds resolve a fresh dependency "
        "graph every run; a transient rubygems.org-side bad "
        "patch release lands on the build the moment it's "
        "published. The 2019 rest-client maintainer compromise "
        "(CVE-2019-15224) was time-bounded; only consumers "
        "without a committed Gemfile.lock had any chance of "
        "pulling the bad patch.",
    ),
    exploit_example=(
        "# Vulnerable: lockfile excluded from version control.\n"
        "$ cat .gitignore\n"
        "Gemfile.lock\n"
        "\n"
        "# Risk: every CI ``bundle install`` re-resolves\n"
        "# floating ``~>`` constraints. A poisoned patch release\n"
        "# published upstream is picked up the moment CI next\n"
        "# runs; rolled back at the next build once rubygems\n"
        "# yanks the version. No diff, no reproducer.\n"
        "\n"
        "# Safe: commit Gemfile.lock. Combined with exact-pin\n"
        "# constraints in the Gemfile (GEM-002), reproducibility\n"
        "# is locked at the cost of explicit ``bundle update``\n"
        "# calls when upgrades are wanted."
    ),
)


def check(pom: GemFile) -> Finding:
    if not pom.dependencies:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Gemfile declares no dependencies; absent "
                "Gemfile.lock is a no-op."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if pom.has_lockfile:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=f"Lockfile present at ``{pom.lockfile_path}``.",
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"No Gemfile.lock alongside ``{pom.path}``. Every "
            f"``bundle install`` re-resolves the manifest; a "
            f"poisoned patch release upstream is silently picked "
            f"up on the next run."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
