"""GEM-005. ``gem`` with git: / github: source missing a ref SHA pin."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-005",
    title="Gemfile gem with git: / github: source missing a ref SHA pin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Replace ``branch:`` / ``tag:`` / no-ref-at-all with "
        "``ref: \"<40-char SHA>\"``. A branch head can be "
        "force-pushed; a tag can be deleted and re-created "
        "pointing at a different commit; ``master`` / ``main`` "
        "(the default when no ref is given) is the most mutable "
        "of all. Only a commit SHA is content-addressable. After "
        "the bump, ``bundle update <gemname>`` to refresh the "
        "lockfile so the Gemfile.lock revision agrees with the "
        "Gemfile pin."
    ),
    docs_note=(
        "Fires when a ``gem`` entry has a ``git:`` URL or "
        "``github:`` shorthand and the entry doesn't carry a "
        "``ref:`` option. ``branch:`` / ``tag:`` are treated as "
        "mutable refs (which they are). The lockfile pins the "
        "resolved SHA at install time, so the immediate risk is "
        "lower than the un-locked manifest case, but anyone "
        "running ``bundle update`` after a hostile force-push "
        "ingests the attacker's commit."
    ),
    known_fp=(
        "Internal monorepos where the ``git:`` source is a "
        "trusted internal repo with branch-protection rules in "
        "place may accept the lower assurance of a "
        "branch / tag pin. Suppress with a one-line rationale "
        "naming the branch-protection guarantee.",
    ),
    incident_refs=(
        "Maintainer-account-compromise on a public repo lets "
        "the attacker force-push the named branch. The ``ref: "
        "\"<sha>\"`` pin is the one assurance that survives a "
        "compromise of the upstream account.",
    ),
    exploit_example=(
        "# Vulnerable: git source, no ref pin.\n"
        "gem \"some-gem\", github: \"owner/some-gem\"\n"
        "gem \"other\", git: \"https://github.com/x/other\", "
        "branch: \"main\"\n"
        "\n"
        "# Risk: hostile force-push to main propagates to every\n"
        "# consumer the next time they ``bundle update``.\n"
        "\n"
        "# Safe: SHA pin.\n"
        "gem \"some-gem\", github: \"owner/some-gem\", "
        "ref: \"a1b2c3d4e5f6...\""
    ),
)


def check(pom: GemFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.is_git:
            continue
        if not dep.git_mutable:
            continue
        offenders.append((dep.name, dep.git_url or "<git>"))
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = "All git / github gem sources pin a ref SHA."
    else:
        rendered = ", ".join(
            f"{name}@{url}" for name, url in offenders[:3]
        )
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} git / github gem source(s) pin a "
            f"mutable ref: {rendered}{suffix}. Replace branch / "
            f"tag with ``ref: \"<sha>\"``."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
