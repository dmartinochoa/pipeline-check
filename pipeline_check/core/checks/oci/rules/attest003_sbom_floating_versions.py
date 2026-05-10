"""ATTEST-003. Attached SBOM declares dependencies with floating versions."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Attestation, OCIManifest

RULE = Rule(
    id="ATTEST-003",
    title="SBOM contains floating-version dependencies",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS", "ESF-S-SBOM"),
    cwe=("CWE-1357", "CWE-1104"),
    recommendation=(
        "Pin every dependency in the SBOM to a concrete version (a "
        "released semver, a digest, or a tag-plus-commit pair). "
        "Floating values like ``latest``, ``*``, ``master``, an "
        "empty string, or a bare major like ``v1`` defeat the SBOM's "
        "purpose: a consumer can't reproduce or vulnerability-scan "
        "what they don't have a fixed version of. SPDX 2.x carries "
        "version under ``packages[*].versionInfo``; CycloneDX uses "
        "``components[*].version``. Both fields are optional in the "
        "spec but operationally required for any meaningful SBOM "
        "consumption."
    ),
    docs_note=(
        "ATTEST-001 verifies the builder; ATTEST-002 verifies the "
        "source; ATTEST-003 verifies the *contents* of what was "
        "shipped. A signed SBOM that declares ``openssl`` version "
        "``latest`` is worse than no SBOM, the signature gives the "
        "rot a stamp of approval. Vulnerability-scanning tooling "
        "that reads the SBOM produces false negatives because the "
        "version it queries CVE databases for is unstable.\n\n"
        "Detection walks every SBOM attestation (predicate types "
        "starting with ``https://spdx.dev/Document`` or "
        "``https://cyclonedx.org/bom``) and checks each declared "
        "package's version field against a floating-shape regex. "
        "A package is considered pinned when its version matches a "
        "concrete release identifier (semver, calver, sha-style "
        "digest, or any git tag with at least one numeric "
        "component)."
    ),
    known_fp=(
        "Some SBOM emitters legitimately leave ``versionInfo`` empty "
        "for system-injected components the build couldn't resolve "
        "(e.g. ``glibc`` from the base image when the image was "
        "built without distro metadata). Suppress via ignore-file "
        "scoped to the manifest path when the SBOM was produced in "
        "a context that intentionally elides those entries; for "
        "production-bound images the expectation is full version "
        "coverage.",
        "Source-only components (a Git repo bundled into a builder "
        "stage) sometimes carry the branch name in version. Long-"
        "term that's still a floating reference (the branch tip "
        "moves), so the rule fires by design; switch to "
        "tag+digest pinning before suppressing.",
    ),
    incident_refs=(
        "Log4Shell (CVE-2021-44228) downstream impact: organizations "
        "with SBOMs at the ready could ship patches in hours; those "
        "without (or with floating-version SBOMs) spent days "
        "auditing builds to discover what they actually shipped. "
        "The ``log4j-core@latest`` shape was the worst case, the "
        "SBOM said the right name but no consumer could pin which "
        "exact bytes were in production. "
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a",
        "Common SBOM-quality findings (NTIA SBOM Minimum Elements "
        "report, 2021): version completeness consistently the "
        "lowest-scoring dimension across producers. Floating "
        "versions account for the bulk of unconsumed SBOMs in "
        "vulnerability-management pipelines.",
    ),
)


# ── Floating-version detection ──────────────────────────────────────


# Tokens that are unambiguously floating regardless of where they
# appear. Lowercased before comparison.
_FLOATING_TOKENS: frozenset[str] = frozenset({
    "", "latest", "*", "master", "main", "develop", "dev", "head",
    "trunk", "stable", "edge", "current", "rolling",
})

# A pinned version is anything matching one of these patterns:
#   - semver / extended semver:  ``1.2.3``, ``1.2.3-rc4``,
#                                ``1.2.3+build.5``, ``v1.2.3``
#   - calver:                    ``2026.05``, ``20260510``
#   - hex digest:                32+ hex chars (truncated SHA-1 or
#                                full SHA-256)
#   - any string containing at least two numeric components
#     separated by ``.`` (catches ``3.12``, ``v3.12.1-slim``)
_PINNED_VERSION_RE = re.compile(
    r"""
    ^v?\d+\.\d+(\.\d+)?            # ``1.2`` / ``1.2.3`` / ``v1.2.3``
        ([\-+][\w\.\-]+)?$         #   optional pre-release / build
    | ^[0-9a-f]{32,}$              # hex digest (32+ chars)
    | ^\d{4}\.\d{2}(\.\d+)?$       # calver: ``2026.05`` / ``2026.05.10``
    | ^\d{8}$                      # calver compact: ``20260510``
    """,
    re.VERBOSE | re.IGNORECASE,
)

# A bare major like ``v1`` or ``1`` is floating (the producer can ship
# a different ``1.x`` next week without changing the version string).
_BARE_MAJOR_RE = re.compile(r"^v?\d+$")


def _classify_version(version: str | None) -> str:
    """Return ``'floating'`` / ``'pinned'``.

    A None or empty string counts as floating because the SBOM
    consumer has nothing to query.

    Order of checks matters: the pinned regex runs before the bare-
    major check so an 8-digit calver (``20260510``) doesn't get
    misclassified as a bare major. Floating-token / placeholder
    checks run first so ``latest`` etc. always lose.
    """
    if version is None:
        return "floating"
    stripped = version.strip()
    if stripped.lower() in _FLOATING_TOKENS:
        return "floating"
    if _PINNED_VERSION_RE.match(stripped):
        return "pinned"
    if _BARE_MAJOR_RE.match(stripped):
        return "floating"
    # Any other string: heuristic. Treat as pinned only when it
    # contains at least one digit (so ``unknown-build`` is floating
    # but ``release-2025-Q1-rc7`` passes).
    if any(c.isdigit() for c in stripped):
        return "pinned"
    return "floating"


def _spdx_version_pairs(predicate: dict[str, Any]) -> list[tuple[str, str | None]]:
    """Return ``(package_name, version_or_None)`` from an SPDX predicate."""
    out: list[tuple[str, str | None]] = []
    packages = predicate.get("packages")
    if not isinstance(packages, list):
        return out
    for p in packages:
        if not isinstance(p, dict):
            continue
        name_val = p.get("name")
        name = name_val if isinstance(name_val, str) and name_val else "?"
        version_val = p.get("versionInfo")
        version = version_val if isinstance(version_val, str) else None
        out.append((name, version))
    return out


def _cyclonedx_version_pairs(predicate: dict[str, Any]) -> list[tuple[str, str | None]]:
    """Return ``(component_name, version_or_None)`` from a CycloneDX predicate."""
    out: list[tuple[str, str | None]] = []
    components = predicate.get("components")
    if not isinstance(components, list):
        return out
    for c in components:
        if not isinstance(c, dict):
            continue
        name_val = c.get("name")
        name = name_val if isinstance(name_val, str) and name_val else "?"
        version_val = c.get("version")
        version = version_val if isinstance(version_val, str) else None
        out.append((name, version))
    return out


def _version_pairs(att: Attestation) -> list[tuple[str, str | None]]:
    """Dispatch to the SPDX or CycloneDX extractor."""
    if att.predicate_type.startswith("https://spdx.dev/Document"):
        return _spdx_version_pairs(att.predicate)
    if att.predicate_type.startswith("https://cyclonedx.org/bom"):
        return _cyclonedx_version_pairs(att.predicate)
    return []


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "SBOM verification not applicable."
            ),
            recommendation="No action required.", passed=True,
        )

    sbom_attestations = [a for a in manifest.attestations if a.is_sbom]
    if not sbom_attestations:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No SBOM attestation content available to verify "
                "dependency pinning. Pass an OCI image-layout "
                "directory with a sibling ``blobs/`` tree to enable "
                "content checks; OCI-002 covers the missing-"
                "attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    floating: list[str] = []
    examined = 0
    for att in sbom_attestations:
        for name, version in _version_pairs(att):
            examined += 1
            if _classify_version(version) == "floating":
                rendered = (
                    f"{name}@{version}"
                    if version not in (None, "")
                    else f"{name}@<empty>"
                )
                floating.append(rendered)

    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"{len(sbom_attestations)} SBOM attestation(s) "
                f"present but contain no enumerable packages / "
                f"components. Confirm the SBOM emitter is wired in "
                f"correctly (an empty ``packages`` / ``components`` "
                f"list defeats SBOM verification)."
            ),
            recommendation=RULE.recommendation, passed=False,
        )

    if not floating:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {examined} component(s) across "
                f"{len(sbom_attestations)} SBOM attestation(s) "
                f"carry pinned versions."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(floating)} of {examined} SBOM component(s) declare "
        f"floating versions: {', '.join(sorted(set(floating))[:5])}"
        f"{'…' if len(floating) > 5 else ''}. A consumer can't "
        f"vulnerability-scan or reproduce code pinned to a moving "
        f"reference."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
