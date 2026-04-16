"""JF-001 — @Library references must be pinned to a tag or commit."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import FLOATING_REFS, PINNED_REF_RE


RULE = Rule(
    id="JF-001",
    title="Shared library not pinned to a tag or commit",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    recommendation=(
        "Pin every `@Library('name@<ref>')` to a release tag (e.g. "
        "`@v1.4.2`) or a 40-char commit SHA. Configure the library "
        "in Jenkins with 'Allow default version to be overridden' "
        "disabled so a pipeline can't escape the pin."
    ),
    docs_note=(
        "`@main`, `@master`, `@develop`, no-`@ref`, and any "
        "non-semver / non-SHA ref are floating. Whoever controls "
        "the upstream library can ship code into your build by "
        "pushing to that branch."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    unpinned: list[str] = []
    for spec in jf.library_refs:
        if "@" not in spec:
            unpinned.append(f"{spec} (no @ref)")
            continue
        _, ref = spec.rsplit("@", 1)
        if ref.lower() in FLOATING_REFS or not PINNED_REF_RE.match(ref):
            unpinned.append(spec)
    passed = not unpinned
    desc = (
        "Every @Library reference is pinned to a tag or commit SHA."
        if passed else
        f"{len(unpinned)} @Library reference(s) point at a floating "
        f"branch or default ref: {', '.join(sorted(set(unpinned))[:5])}"
        f"{'…' if len(set(unpinned)) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
