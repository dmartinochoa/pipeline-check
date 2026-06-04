"""GL-042, `include: component:` must pin an immutable version."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GL-042",
    title="include: component pulls a CI/CD component without a pinned version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every `include: component:` to an immutable version: a "
        "40-character commit SHA, or a full release tag (`X.Y.Z`) on a "
        "component project that enforces tag protection. A mutable "
        "version (`~latest`, a branch like `main`, or a floating major / "
        "minor like `1` / `1.2`) lets whoever controls the component "
        "project re-point that reference and ship arbitrary pipeline "
        "code into every consumer's next pipeline, running with the "
        "consumer's `CI_JOB_TOKEN` and CI/CD variables. Bump pins in "
        "reviewable MRs (Renovate's GitLab CI/CD component updater "
        "supports this)."
    ),
    docs_note=(
        "GitLab CI/CD components are third-party pipeline code merged "
        "into the consumer's pipeline before any job runs. The version "
        "in `include: component: <host>/<path>@<version>` resolves like a "
        "dependency ref: `~latest` (the latest release), a branch, and a "
        "floating major / minor are all mutable; a full `X.Y.Z` tag or a "
        "40-char commit SHA are pinned. Fires when the `@<version>` is "
        "missing, `~latest`, branch-shaped, or a partial version. The "
        "same supply-chain class as GL-005 (remote / project includes) "
        "and GL-030 (trigger includes), through the newer component "
        "surface those two rules don't inspect."
    ),
    exploit_example=(
        "# Vulnerable: the component is pinned to a mutable reference.\n"
        "# Whoever controls the component project re-points ``~latest``\n"
        "# (or pushes to the branch) and their script: runs in this\n"
        "# pipeline with its CI_JOB_TOKEN and variables.\n"
        "include:\n"
        "  - component: gitlab.example.com/ci/security/scan@~latest\n"
        "\n"
        "# Attack: the component author (or anyone who compromises the\n"
        "# component repo) ships a before_script that exfiltrates the\n"
        "# job token / dumps the environment on the consumer's next run.\n"
        "\n"
        "# Safe: pin to a release tag (tag-protected) or a commit SHA.\n"
        "include:\n"
        "  - component: gitlab.example.com/ci/security/scan@1.4.2\n"
        "  - component: gitlab.example.com/ci/security/lint@0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"
    ),
)

# A 40-char hex commit SHA, or a full ``X.Y.Z`` semver tag (optional
# leading ``v`` and a prerelease / build suffix). Either is immutable
# enough to pin a component; anything else (``~latest``, a branch, a
# partial ``1`` / ``1.2``) is mutable.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


def _component_version(value: str) -> str | None:
    """Return the ``@<version>`` of a component string, or ``None``."""
    # The host / group / project / component path carries no ``@``; the
    # version separator is the last ``@``.
    if "@" not in value:
        return None
    return value.rsplit("@", 1)[1].strip()


def _is_pinned(version: str) -> bool:
    return bool(_SHA_RE.match(version) or _SEMVER_RE.match(version))


def check(path: str, doc: dict[str, Any]) -> Finding:
    includes = doc.get("include")
    if includes is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline has no `include:` directive.",
            recommendation="No action required.", passed=True,
        )
    items = includes if isinstance(includes, list) else [includes]
    unpinned: list[str] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        comp = entry.get("component")
        if not isinstance(comp, str) or not comp.strip():
            continue
        version = _component_version(comp)
        if version is None:
            unpinned.append(f"{comp} (no @version)")
        elif not _is_pinned(version):
            unpinned.append(f"{comp} (@{version} is mutable)")
    passed = not unpinned
    desc = (
        "Every `include: component:` pins an immutable version (SHA or X.Y.Z tag)."
        if passed else
        f"{len(unpinned)} component include(s) use a mutable version: "
        f"{', '.join(unpinned[:5])}{'…' if len(unpinned) > 5 else ''}. "
        f"Whoever controls the component project can re-point it and run "
        f"arbitrary pipeline code with this project's CI_JOB_TOKEN."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
