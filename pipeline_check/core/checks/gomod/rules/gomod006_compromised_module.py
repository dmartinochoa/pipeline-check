"""GOMOD-006. go.mod requires a known-compromised module version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_modules import lookup
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-006",
    title="go.mod requires a known-compromised module version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Bump the offending require to a patched version (named "
        "in the cited advisory) and run ``go mod tidy`` to refresh "
        "the integrity manifest. If the advisory has no patched "
        "release, pin to the last known-good version and add a "
        "follow-up TODO so the dependency is replaced or removed "
        "the next maintenance cycle. After the bump, re-run the "
        "scan, GOMOD-006 should clear; if the rule still fires, "
        "an indirect require somewhere is pulling the bad version "
        "back in. Use ``go mod why -m <module>@<version>`` to "
        "find the path."
    ),
    docs_note=(
        "Reads the curated registry under "
        "``pipeline_check.core.checks.gomod._compromised_modules`` "
        "(table of ``(module_path, malicious_versions, advisory)`` "
        "entries) and fires when any require — direct or indirect "
        "— matches an entry. The registry is hand-curated and "
        "append-only; adding a new entry is a one-line table edit "
        "plus the citing advisory in the commit message.\n\n"
        "Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005: the "
        "rule fires on exact version equality (with optional "
        "regex-fallback patterns shared via ``_primitives/"
        "compromised.py``). Coverage is necessarily incomplete; "
        "the value is the audit-trail-locked post-incident "
        "detection of a published advisory, complementing the "
        "live OSV-advisory rule that would land alongside any "
        "future ``--resolve-remote`` extension."
    ),
    known_fp=(
        "Patched fork-and-pin remediation paths sometimes legitimately "
        "leave the original module name pinned at an affected "
        "version (with a same-module replace pointing at the "
        "fork). The rule still fires on the require line; suppress "
        "per directive with a one-line rationale naming the replace "
        "fork and the advisory the patch covers.",
    ),
    incident_refs=(
        "CVE-2025-22869 (GHSA-v778-237x-gjrc): golang.org/x/crypto "
        "ScalarMult vulnerability in pre-0.32.0 patch versions. "
        "Future entries follow the same shape: append the "
        "(module_path, version, advisory) row to "
        "_compromised_modules.py and cite the GHSA in the commit "
        "message.",
    ),
    exploit_example=(
        "// Vulnerable: an exact require pinned at a version named\n"
        "// in a published GHSA.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require golang.org/x/crypto v0.0.0-20240909161250-f395bea34c2d\n"
        "\n"
        "// Attack: the published GHSA enumerates the affected\n"
        "// versions; an attacker who can route traffic through\n"
        "// the vulnerable code path triggers the cryptographic\n"
        "// flaw (in the case of GHSA-v778-237x-gjrc, a ScalarMult\n"
        "// edge case that leaks private-key bits).\n"
        "\n"
        "// Safe: bump to the patched release.\n"
        "//   require golang.org/x/crypto v0.32.0\n"
        "// Then ``go mod tidy`` and commit the refreshed go.sum."
    ),
)


def check(pom: GoModFile) -> Finding:
    offenders: list[tuple[str, str, str]] = []
    locations: list[Location] = []
    for req in pom.requires:
        entry = lookup(req.path, req.version)
        if entry is None:
            continue
        offenders.append((req.path, req.version, entry.advisory))
        locations.append(Location(
            path=pom.path,
            start_line=req.line_no,
            end_line=req.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No require entries match the curated compromised-"
            "module registry."
        )
    else:
        rendered = ", ".join(
            f"{path}@{ver} ({advisory})"
            for path, ver, advisory in offenders[:5]
        )
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} require(s) match a known-compromised "
            f"registry entry: {rendered}{suffix}. Bump to a patched "
            f"version named in the cited advisory and refresh "
            f"go.sum."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
