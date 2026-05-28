"""COMPOSER-001. composer.json present without a sibling composer.lock."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-001",
    title="composer.json present without a sibling composer.lock",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "For applications, commit ``composer.lock`` to the "
        "repository. The lockfile records the exact resolved "
        "version of every transitive dependency, so every "
        "``composer install`` (locally and in CI) installs the "
        "same code. Without it, ``composer install`` resolves "
        "the manifest fresh each time and is free to pick the "
        "latest matching patch under any floating constraint "
        "(COMPOSER-002). \n\n"
        "For libraries published to Packagist, Composer's "
        "guidance is the opposite — leave composer.lock "
        "uncommitted so downstream consumers can resolve. The "
        "default posture (composer.lock committed) is correct "
        "for applications, internal services, CLI tools, and "
        "Symfony / Laravel / WordPress projects."
    ),
    docs_note=(
        "Fires when the manifest's directory has no "
        "``composer.lock`` sibling. Libraries that legitimately "
        "publish without a lockfile need a per-file suppression "
        "with a one-line rationale naming the "
        "library-as-published posture."
    ),
    known_fp=(
        "Library packages published to Packagist intentionally "
        "omit composer.lock from version control so downstream "
        "applications can deduplicate transitive deps; this rule "
        "fires on those, suppress per package with a one-line "
        "rationale.",
    ),
    incident_refs=(
        "Long-running pattern of PHP applications that ignore "
        "composer.lock in .gitignore (a habit imported from "
        "library development). CI builds resolve a fresh graph "
        "every run; a transient registry-side bad patch release "
        "lands on the build the moment it's published, then "
        "disappears on the next run, leaving no audit trail and "
        "no reproducer.",
    ),
    exploit_example=(
        "# Vulnerable: lockfile excluded from version control.\n"
        "$ cat .gitignore\n"
        "composer.lock\n"
        "\n"
        "# Risk: every CI ``composer install`` re-resolves the\n"
        "# graph. A poisoned patch release published upstream is\n"
        "# picked up the moment CI next runs; rolled back at the\n"
        "# next build once Packagist pulls the version. No diff,\n"
        "# no reproducer, no audit trail.\n"
        "\n"
        "# Safe: commit composer.lock. Combined with exact-pin\n"
        "# constraints in composer.json (COMPOSER-002),\n"
        "# reproducibility is locked at the cost of explicit\n"
        "# ``composer update`` calls when upgrades are wanted."
    ),
)


def check(pom: ComposerFile) -> Finding:
    if not pom.dependencies:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "composer.json declares no dependencies; absent "
                "composer.lock is a no-op."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if pom.has_lockfile:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"Lockfile present at ``{pom.lockfile_path}``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"No composer.lock alongside ``{pom.path}``. Every "
            f"``composer install`` re-resolves the manifest; a "
            f"poisoned patch release upstream is silently picked "
            f"up on the next run."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
