"""CC-001. Orbs must be pinned to an exact semver (x.y.z)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ._helpers import PINNED_ORB_RE, VOLATILE_ORB_RE

RULE = Rule(
    id="CC-001",
    title="Orb not pinned to exact semver",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every orb to an exact semver version (`circleci/node@5.1.0`). "
        "Floating references like `@volatile`, `@1`, or bare names without "
        "`@` resolve to whatever is latest at build time, allowing a "
        "compromised orb update to execute in the pipeline."
    ),
    docs_note=(
        "Orb references in the `orbs:` block must include an `@x.y.z` "
        "suffix to lock a specific version. References without `@`, with "
        "`@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) "
        "version float and can silently pull in malicious updates."
    ),
    exploit_example=(
        "# Vulnerable: ``circleci/aws-cli@volatile`` (or any non-\n"
        "# semver ref) resolves at config-process time to whatever\n"
        "# the orb publisher last pushed. A compromised publisher\n"
        "# ships malicious orb steps into every consumer's pipeline.\n"
        "version: 2.1\n"
        "orbs:\n"
        "  aws-cli: circleci/aws-cli@volatile\n"
        "  python: circleci/python@dev:alpha\n"
        "\n"
        "# Safe: pin to an exact semver (``X.Y.Z``). Renovate's\n"
        "# circleci ecosystem updater bumps the pin in reviewable\n"
        "# PRs; ``@volatile`` and ``@dev:*`` never reach prod.\n"
        "version: 2.1\n"
        "orbs:\n"
        "  aws-cli: circleci/aws-cli@4.1.3\n"
        "  python: circleci/python@2.1.1"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    orbs = doc.get("orbs") or {}
    if not isinstance(orbs, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No orbs declared in the config.",
            recommendation="No action required.", passed=True,
        )
    unpinned: list[str] = []
    for _alias, ref in orbs.items():
        if not isinstance(ref, str):
            # Inline orb definitions (dict) are local, skip.
            continue
        if "@" not in ref or VOLATILE_ORB_RE.search(ref) or not PINNED_ORB_RE.search(ref):
            unpinned.append(ref)
    passed = not unpinned
    desc = (
        "Every orb reference is pinned to an exact semver version."
        if passed else
        f"{len(unpinned)} orb reference(s) are not pinned to exact "
        f"semver: {', '.join(sorted(set(unpinned))[:5])}"
        f"{'...' if len(set(unpinned)) > 5 else ''}. "
        f"Floating references can silently pull in compromised updates."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
