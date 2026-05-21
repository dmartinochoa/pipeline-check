"""XPC-009. Ingested CVE finding plus mutable runtime image
(any ``INGEST-trivy-CVE-*`` / ``INGEST-grype-CVE-*`` / similar
CVE-shaped ingested finding + ``DF-001``).

The first cross-tool chain. Demonstrates the ``--ingest`` flag's
strategic value: pipeline-check correlates a CVE finding from a
SARIF feed (Trivy / Grype / Snyk container scan) with its own
Dockerfile-mutability finding to produce a composite the
individual tools wouldn't surface alone.

Fires when both:

  * Any ``INGEST-trivy-CVE-*`` / ``INGEST-grype-CVE-*`` /
    ``INGEST-snyk-SNYK-*`` finding is in the union — a CVE-shaped
    finding from one of the common container scanners; AND
  * ``DF-001`` — the Dockerfile's ``FROM`` line references a
    floating tag rather than a digest.

Independently each leg is one tool's job:
  * Trivy / Grype find CVEs in the layers the team's CURRENT
    image ships.
  * pipeline-check's DF-001 says the team's image is pinned by
    a floating tag, so future builds get whatever bytes the
    upstream tag points to.

Together they say: not only is your current image known
vulnerable, but you can't reliably bound the vulnerability set
of the next build. A digest pin would at least keep the
vulnerability snapshot consistent across builds; a floating tag
means the team can't know whether tomorrow's build is the same
shape as today's. The remediation is two-part: pin to a digest
AND update the digest to a known-clean upstream version.

This chain currently activates when scanning ``--pipelines
dockerfile`` (or any pipeline_check run with a Dockerfile in
scope) together with ``--ingest <trivy.sarif>`` (or any
container-scan SARIF that produces ``INGEST-<tool>-CVE-*``
findings).

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The ingest finding lives on
the SARIF feed's ``location.uri`` (typically an image-tag string
the external scanner produced), the DF finding lives on a
Dockerfile path, the two halves never share a CI job because the
SARIF feed was produced by a different tool's run. Per-scan
co-occurrence is the reachability claim, today's known
vulnerability AND tomorrow's unbounded image content land in the
same operator's queue.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, failing_prefix, min_confidence

#: Prefixes the chain treats as "CVE-shaped ingested findings."
#: Hand-curated to the major container scanners' SARIF formats;
#: extend the tuple to broaden cross-tool coverage. The shape is
#: a substring match against the SARIF-derived check_id, so a
#: scanner whose rule IDs already encode "CVE" anywhere in the
#: identifier is caught.
_CVE_PREFIXES: tuple[str, ...] = (
    "INGEST-trivy-CVE-",
    "INGEST-trivy-AVD-",        # Trivy's Aqua Vulnerability DB IDs
    "INGEST-grype-CVE-",
    "INGEST-snyk-SNYK-",
    "INGEST-snyk-CVE-",
    "INGEST-clair-CVE-",
    "INGEST-anchore-CVE-",
)

RULE = ChainRule(
    id="XPC-009",
    title="Ingested CVE finding plus mutable runtime image reference",
    severity=Severity.HIGH,
    summary=(
        "A SARIF feed (Trivy, Grype, Snyk, etc.) reports at least "
        "one CVE against the current image AND the Dockerfile pins "
        "its base by floating tag rather than digest. Today's "
        "vulnerability set is known; tomorrow's is unbounded. "
        "Pinning to a digest keeps the vulnerability snapshot "
        "reproducible across builds; updating the digest is then "
        "a deliberate, auditable action."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1525",      # Implant Internal Image
    ),
    kill_chain_phase=(
        "supply-chain (current-image vulnerability + unbounded "
        "future-image content)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10",
    ),
    recommendation=(
        "Two fixes; both are needed to close the chain:\n"
        "  1. Pin the Dockerfile's ``FROM`` to a digest "
        "(``FROM python:3.12@sha256:<hex>``) (DF-001). The build "
        "then uses the exact bytes the digest names; no upstream "
        "tag-rewrite changes the vulnerability set.\n"
        "  2. Update the digest to a known-clean upstream version "
        "the SARIF scanner clears. Capture the digest with "
        "``crane digest`` or ``docker buildx imagetools inspect`` "
        "and update the ``FROM`` line in version control. The next "
        "build then uses the patched image AND keeps the snapshot "
        "consistent across subsequent runs.\n"
        "Optional but valuable: wire Dependabot or Renovate to "
        "auto-PR the digest update when a new clean version "
        "publishes (SCM-005 + this chain together close the loop)."
    ),
    providers=("dockerfile",),
    # Synthetic triggering_check_ids: the prefix-matched ingested
    # findings have variable suffixes (one per CVE), so we list the
    # prefix bases here for ``--explain`` discoverability. The
    # ``match()`` function does the actual prefix-walk.
    triggering_check_ids=("DF-001",) + _CVE_PREFIXES,
)


def _tool_slug_from_check_id(check_id: str) -> str:
    """Recover the source-tool slug from an ingested ``INGEST-*``
    check_id by matching against the known prefix set, so hyphenated
    tool names (``codeql-cli``, future ``grype-db``, etc.) round-trip
    instead of collapsing to their first segment. Falls back to a
    tool-neutral phrase when the check_id doesn't fit the convention.
    """
    for prefix in _CVE_PREFIXES:
        if check_id.startswith(prefix):
            # Prefix shape is ``INGEST-<tool>-<id-marker>-`` —
            # strip ``INGEST-`` and the trailing ``-<id-marker>-`` to
            # recover ``<tool>`` verbatim, hyphens intact.
            inner = prefix[len("INGEST-"):].rstrip("-")
            tool, _, _ = inner.rpartition("-")
            if tool:
                return tool
    return "an ingested scanner"


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one CVE-shaped ingested finding AND one
    DF-001 fail in the same run.

    One composite per ``(cve_finding, df_finding)`` cross-product
    cell. For SARIF feeds with hundreds of CVEs this produces a
    chain per ``(CVE, Dockerfile)`` pair; the operator gets one
    triage entry per pair to audit.
    """
    cve_legs = failing_prefix(findings, *_CVE_PREFIXES)
    df_legs = failing(findings, "DF-001")
    if not cve_legs or not df_legs:
        return []

    out: list[Chain] = []
    for cve_finding in cve_legs:
        for df_finding in df_legs:
            triggers = [cve_finding, df_finding]
            tool = _tool_slug_from_check_id(cve_finding.check_id)
            narrative = (
                f"Cross-tool chain:\n"
                f"  1. {tool} reports CVE-shaped finding "
                f"`{cve_finding.check_id}` against "
                f"`{cve_finding.resource}`. The image the team "
                f"currently ships has a known vulnerability.\n"
                f"  2. Dockerfile `{df_finding.resource}` "
                f"references its base image by floating tag rather "
                f"than digest (DF-001). The next build pulls "
                f"whatever bytes the upstream registry currently "
                f"serves under that tag; the vulnerability set "
                f"from one build to the next can drift silently.\n"
                f"  3. Composite: today's known vulnerability AND "
                f"unbounded future-image content. Pinning the "
                f"digest keeps the vulnerability snapshot "
                f"reproducible and lets the team track "
                f"remediation as a deliberate digest update; "
                f"without it, the ingested-scanner results carry "
                f"an asterisk because the next build won't "
                f"necessarily have the same layers."
            )
            out.append(Chain(
                chain_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                confidence=min_confidence(triggers),
                summary=RULE.summary,
                narrative=narrative,
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=[
                    cve_finding.check_id, df_finding.check_id,
                ],
                triggering_findings=triggers,
                resources=[cve_finding.resource, df_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
