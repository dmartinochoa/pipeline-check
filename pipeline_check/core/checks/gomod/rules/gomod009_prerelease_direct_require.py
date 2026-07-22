"""GOMOD-009. Direct require uses a pre-release version."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile, iter_direct_requires

RULE = Rule(
    id="GOMOD-009",
    title="Direct require uses a pre-release version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin every production direct dependency to a stable "
        "release. Pre-release versions (``v1.0.0-rc.1``, "
        "``v2.0.0-alpha.3``, ``v0.9.0-beta``) signal that the "
        "upstream maintainer hasn't committed to API or "
        "behavioral stability for the tag — a patch may revert "
        "or rewrite the suffix, and security advisories "
        "specifically scope to released versions, so a stuck "
        "pre-release ships with no patched-version migration "
        "path.\n\n"
        "If the project legitimately needs the pre-release "
        "(awaiting an upstream stable that ships a critical "
        "fix), document the dependency with a follow-up TODO "
        "pointing at the upstream's stabilization issue and "
        "revisit on every scan."
    ),
    docs_note=(
        "Matches the standard semver pre-release suffix shape "
        "on direct requires: ``-rc``, ``-alpha``, ``-beta``, "
        "``-pre``, ``-dev`` (case-insensitive) anywhere after the "
        "``vX.Y.Z`` head. Pseudo-versions "
        "(``v0.0.0-YYYYMMDDHHMMSS-commitsha``) are excluded — "
        "they're Go's canonical mechanism for pinning to a "
        "commit when the upstream has no tagged release yet, "
        "and the rule would FP on the most common form of "
        "intentional pre-release usage.\n\n"
        "Indirect requires (``// indirect``) are exempt; the "
        "consumer doesn't directly control the version and "
        "auditing them dilutes the rule's signal."
    ),
    known_fp=(
        "Libraries that exclusively ship pre-release tags "
        "(some experimental projects use ``v0.x``-style major "
        "zero versioning forever) trip this rule by design. "
        "Suppress per dependency with a one-line rationale "
        "naming the upstream's stabilization policy.",
    ),
    incident_refs=(
        "Pattern in early-stage Go projects where a contributor "
        "pulls in an upstream's release-candidate during "
        "development, the project ships, and the dependency "
        "stays at ``-rc`` for years past the upstream's GA "
        "release. Security advisories typically don't cover "
        "pre-release tags, so the consumer remains exposed to "
        "fixed-in-stable vulnerabilities indefinitely.",
    ),
    exploit_example=(
        "// Vulnerable: pre-release pinned in production.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require github.com/foo/bar v2.0.0-rc.1\n"
        "\n"
        "// Risk: an upstream advisory documents a fix in v2.0.0\n"
        "// (the stable release). The consumer's pre-release pin\n"
        "// stays at v2.0.0-rc.1 forever; the fix never lands\n"
        "// without an explicit bump.\n"
        "\n"
        "// Safe: bump to stable.\n"
        "require github.com/foo/bar v2.0.0"
    ),
)


# A Go pseudo-version (commit pin) always ends in
# ``<sep><14-digit timestamp>-<commit hash>``. The separator before the
# timestamp is ``-`` (form 1, ``v1.2.3-<ts>-<hash>``) or ``.`` (form 2/3,
# ``v1.2.3-rc.0.<ts>-<hash>`` / ``v1.2.4-0.<ts>-<hash>``), so all three
# forms are recognized as commit pins rather than pre-releases.
_PSEUDO_VERSION_RE = re.compile(r"[-.]\d{14}-[0-9a-f]{12,}$")
# Any SemVer pre-release segment: a ``-`` after the ``vX.Y.Z`` head. This
# covers arbitrary identifiers (rc/alpha/beta/preview/M1/snapshot/canary
# /...), not a fixed keyword list.
_SEMVER_PRERELEASE_RE = re.compile(r"^v\d+\.\d+\.\d+-")


def _is_prerelease(version: str) -> bool:
    if _PSEUDO_VERSION_RE.search(version):
        return False
    return bool(_SEMVER_PRERELEASE_RE.match(version))


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for req in iter_direct_requires(pom):
        if not _is_prerelease(req.version):
            continue
        offenders.append(f"{req.path} {req.version}")
        locations.append(Location(
            path=pom.path,
            start_line=req.line_no, end_line=req.line_no,
        ))
    passed = not offenders
    desc = (
        "No direct require uses a pre-release version suffix."
        if passed else
        f"{len(offenders)} direct require(s) pinned to a "
        f"pre-release tag: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Security "
        f"advisories typically scope to released versions; the "
        f"pre-release pin stays vulnerable without an explicit "
        f"bump."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
