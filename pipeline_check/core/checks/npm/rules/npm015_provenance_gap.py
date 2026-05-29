"""NPM-015, direct dependency published without build provenance."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-015",
    title="Direct dependency published without build provenance",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Build provenance ties a published package back to the source "
        "commit and CI build that produced it (SLSA / npm "
        "`--provenance`), the same guarantee this project ships on its "
        "own wheel. A dependency without it can't be cryptographically "
        "traced to its source, so a registry-side tamper or a "
        "look-alike republish is harder to detect. Prefer dependencies "
        "that publish with provenance where a maintained alternative "
        "exists, and ask upstreams you rely on to adopt it (it is a "
        "one-line change to a GitHub Actions publish job). This is a "
        "posture signal, not a defect in the dependency."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to read each "
        "direct dependency's latest-version `dist.attestations` from "
        "``registry.npmjs.org`` (the same packument fetch NPM-008 and "
        "NPM-014 use, so it adds no extra requests). Flags a package "
        "whose latest version carries no build-provenance attestation. "
        "Scoped to direct dependencies; transitive packages are out of "
        "scope. LOW severity by design: provenance adoption across the "
        "registry is still low, so the absence is common and this is an "
        "informational posture signal that stays below the default "
        "``--fail-on`` gate. When ``--resolve-remote`` is off or the "
        "registry can't be reached, the rule passes silently."
    ),
    known_fp=(
        "A package can be securely published without npm provenance "
        "(e.g. via a different attestation framework, or simply because "
        "it predates provenance support). The absence is a weaker "
        "signal than a present-but-invalid attestation would be. "
        "Suppress per-resource for dependencies whose supply chain the "
        "team has otherwise vetted.",
    ),
    incident_refs=(
        "SLSA provenance / npm `--provenance` (GA 2023): publishing with "
        "provenance produces a signed link from the registry artifact "
        "to the exact source commit and CI run, the property an "
        "attacker who republishes a tampered tarball cannot forge.",
    ),
    exploit_example=(
        "// Risk: ``legacy-lib``'s latest release ships no build\n"
        "// provenance, so there is no signed link from the npm tarball\n"
        "// back to a source commit and CI run. A registry-side tamper\n"
        "// or a maintainer-account republish of a tampered build can't\n"
        "// be detected by verifying provenance, because there is none.\n"
        "// package.json\n"
        "{\n"
        "  \"dependencies\": {\n"
        "    \"legacy-lib\": \"^2.0.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Surface it: ``pipeline_check --pipeline npm\n"
        "// --resolve-remote`` reads each direct dependency's\n"
        "// ``dist.attestations`` from the registry and flags the ones\n"
        "// publishing without provenance, so you can weigh adopting a\n"
        "// provenance-publishing alternative or asking the upstream to\n"
        "// turn it on.\n"
    ),
)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    provenance: dict[str, bool] = ctx.provenance if ctx is not None else {}
    if not provenance:
        # No metadata — silent pass. ``--resolve-remote`` is the opt-in
        # network path; its absence must not fail CI on the default
        # offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No provenance metadata available (re-run with "
                "``--resolve-remote`` to enable provenance analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for section, name, _spec in iter_manifest_dependencies(manifest):
        if name in seen:
            continue  # same dep in two sections — report once
        seen.add(name)
        has_prov = provenance.get(name)
        if has_prov is not False:
            # ``True`` (has provenance) or ``None`` (unresolved) — skip.
            continue
        offenders.append(f"{section}.{name}")
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))

    passed = not offenders
    desc = (
        "Every resolved direct dependency publishes with build provenance."
        if passed else
        f"{len(offenders)} direct dependency / dependencies publish "
        f"without build provenance: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Without a provenance "
        f"attestation the package can't be cryptographically traced "
        f"back to its source commit and CI build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
