"""ATTEST-007. SBOM packages lack supplier / originator attribution.

ATTEST-003 verifies SBOM dependency *versions*. ATTEST-007 verifies
SBOM dependency *origins*: who supplied each package the build
consumed. Without supplier / originator data, a CVE advisory for
"openssl@1.1.1 published by The OpenSSL Project" can't be correlated
against the SBOM because the SBOM doesn't record whose openssl 1.1.1
was actually consumed. Mirror-replay, typosquat, and supply-chain-
poisoning incidents all hinge on the *source* of a package, not just
its name + version.

SPDX puts this under ``packages[*].supplier`` (recommended) and
``packages[*].originator`` (optional). CycloneDX puts it under
``components[*].supplier``. Both specs allow ``NOASSERTION`` as a
sentinel meaning "the producer chose not to populate"; the rule
treats that as effectively missing because it provides no actionable
attribution.

Tolerance: the rule fires when *any* package lacks the field, but
the description summarizes the count. Empty SBOMs and SBOMs with no
packages at all pass-by-default (ATTEST-003 already covers the
empty-SBOM shape).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Attestation, OCIManifest

RULE = Rule(
    id="ATTEST-007",
    title="SBOM packages lack supplier / originator attribution",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"),
    esf=("ESF-S-SBOM", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-1357",),
    recommendation=(
        "Configure the SBOM emitter to populate supplier and "
        "(where applicable) originator fields for every component. "
        "Syft / Trivy / cdxgen all support supplier inference from "
        "package-manager metadata; the field is most often missing "
        "because the generator was invoked without the relevant "
        "ecosystem authority configured. For hand-rolled SBOM "
        "pipelines, derive ``supplier`` from the package registry "
        "(``pkg:npm/foo`` -> ``Organization: https://npmjs.com``) "
        "or the upstream maintainer's published metadata. "
        "``NOASSERTION`` is acceptable only when the package truly "
        "has no identifiable supplier; treating it as a routine "
        "default defeats downstream attribution."
    ),
    docs_note=(
        "Walks every SBOM attestation (SPDX + CycloneDX) and counts "
        "components / packages without supplier attribution. SPDX "
        "checks ``packages[*].supplier``; CycloneDX checks "
        "``components[*].supplier.name`` (the spec uses an object "
        "with a ``name`` key, unlike SPDX's bare string). A package "
        "passes when the field exists, is non-empty, and isn't the "
        "``NOASSERTION`` sentinel.\n\n"
        "Severity LOW because the failure mode is downstream "
        "correlation friction rather than direct execution risk. "
        "Pair with ATTEST-003 (version completeness) for the full "
        "SBOM-quality story; an SBOM that has versions but no "
        "suppliers, or suppliers but no versions, is only half "
        "actionable."
    ),
    known_fp=(
        "Air-gapped builds where the SBOM emitter genuinely "
        "cannot resolve a supplier (private registry without "
        "ecosystem metadata) legitimately ship ``NOASSERTION`` "
        "for affected packages. Suppress per-manifest via "
        "``--ignore-file`` when the gap is documented; the "
        "default expectation for any image promoted to a "
        "production registry is supplier attribution on every "
        "third-party component.",
        "System-injected components (``glibc`` from a distroless "
        "base image, kernel symbols) sometimes carry no supplier "
        "because the SBOM emitter didn't have distro metadata "
        "available. The rule fires by design; the canonical fix "
        "is to provide a supplier of last resort (e.g. the base "
        "image vendor) rather than to suppress.",
    ),
    incident_refs=(
        "[NTIA SBOM Minimum Elements report]"
        "(https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) "
        "(2021): supplier name is listed as a minimum required "
        "element. NTIA's quality assessment of real-world SBOMs "
        "consistently flagged supplier coverage as one of the "
        "lowest-scoring dimensions across producers.",
        "Typosquat and mirror-replay supply-chain incidents (the "
        "broad class behind event-stream, ua-parser-js, and "
        "tj-actions): the attacker substitutes a package whose "
        "name + version match a legitimate one but whose supplier "
        "differs. SBOMs with supplier attribution let downstream "
        "consumers detect the substitution by comparing publisher "
        "identity; SBOMs without it carry no signal at all.",
    ),
)


# Sentinel values both specs allow that the rule treats as missing.
_NO_ATTRIBUTION: frozenset[str] = frozenset({
    "", "noassertion", "noasertion", "none", "n/a", "unknown",
})


def _spdx_missing_supplier(predicate: dict[str, Any]) -> list[str]:
    """Return ``[name, ...]`` of SPDX packages without a usable
    supplier. SPDX's ``supplier`` is a bare string; ``originator``
    is the related field for the original creator (recommended for
    upstream provenance). The rule accepts either as evidence of
    attribution."""
    out: list[str] = []
    packages = predicate.get("packages")
    if not isinstance(packages, list):
        return out
    for p in packages:
        if not isinstance(p, dict):
            continue
        name_val = p.get("name")
        name: str = name_val if isinstance(name_val, str) else "?"
        if _value_attributes(p.get("supplier")):
            continue
        if _value_attributes(p.get("originator")):
            continue
        out.append(name)
    return out


def _cyclonedx_missing_supplier(predicate: dict[str, Any]) -> list[str]:
    """Return ``[name, ...]`` of CycloneDX components without a
    populated ``supplier.name``. CycloneDX's supplier is an object
    rather than a bare string; the spec also allows ``publisher`` as
    a fallback attribution field, so the rule accepts either."""
    out: list[str] = []
    components = predicate.get("components")
    if not isinstance(components, list):
        return out
    for c in components:
        if not isinstance(c, dict):
            continue
        name_val = c.get("name")
        name: str = name_val if isinstance(name_val, str) else "?"
        supplier = c.get("supplier")
        if isinstance(supplier, dict):
            supplier_name = supplier.get("name")
            if _value_attributes(supplier_name):
                continue
        if _value_attributes(c.get("publisher")):
            continue
        out.append(name)
    return out


def _value_attributes(value: Any) -> bool:
    """True iff *value* is a populated, non-sentinel string carrying
    real attribution. Whitespace-only values and ``NOASSERTION``
    placeholders count as missing."""
    if not isinstance(value, str):
        return False
    stripped = value.strip().lower()
    if not stripped:
        return False
    return stripped not in _NO_ATTRIBUTION


def _missing_per_attestation(att: Attestation) -> tuple[str, list[str], int]:
    """Return ``(spec_label, missing_names, examined_count)`` for one
    SBOM attestation. The spec_label is included so the description
    can disambiguate SPDX from CycloneDX in mixed-attestation
    scenarios."""
    if att.predicate_type.startswith("https://spdx.dev/Document"):
        missing = _spdx_missing_supplier(att.predicate)
        total = len(att.predicate.get("packages") or [])
        return "SPDX", missing, total
    if att.predicate_type.startswith("https://cyclonedx.org/bom"):
        missing = _cyclonedx_missing_supplier(att.predicate)
        total = len(att.predicate.get("components") or [])
        return "CycloneDX", missing, total
    return att.predicate_type, [], 0


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "SBOM supplier verification not applicable."
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
                "supplier attribution. Pass an OCI image-layout "
                "directory with a sibling ``blobs/`` tree to enable "
                "content checks; OCI-002 covers the missing-"
                "attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    total_missing: list[str] = []
    total_examined = 0
    for att in sbom_attestations:
        _, missing, examined = _missing_per_attestation(att)
        total_missing.extend(missing)
        total_examined += examined

    if total_examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"{len(sbom_attestations)} SBOM attestation(s) "
                f"present but contain no enumerable packages / "
                f"components. Confirm the SBOM emitter is wired in "
                f"correctly; ATTEST-003 catches the same shape "
                f"from the version-coverage angle."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    if not total_missing:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {total_examined} component(s) across "
                f"{len(sbom_attestations)} SBOM attestation(s) "
                f"declare a supplier."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(total_missing)} of {total_examined} SBOM component(s) "
        f"lack supplier / originator attribution: "
        f"{', '.join(sorted(set(total_missing))[:5])}"
        f"{'…' if len(total_missing) > 5 else ''}. Downstream "
        f"correlation against publisher-identity advisories can't "
        f"distinguish a legitimate package from a typosquat / "
        f"mirror-replay substitute."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
