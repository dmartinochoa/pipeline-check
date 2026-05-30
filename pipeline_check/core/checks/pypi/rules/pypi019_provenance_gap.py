"""PYPI-019, direct dependency published without PEP 740 provenance."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PypiContext, RequirementsFile, iter_specs, requirement_package_name

RULE = Rule(
    id="PYPI-019",
    title="Direct dependency published without PEP 740 provenance",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Build provenance (PEP 740 attestations on PyPI) ties a "
        "published distribution back to the source repository and CI "
        "build that produced it, the same SLSA guarantee this project "
        "ships on its own wheel. A dependency whose latest release "
        "carries no attestation can't be cryptographically traced to "
        "its source, so a registry-side tamper or a look-alike "
        "republish is harder to detect. Prefer dependencies that "
        "publish with attestations where a maintained alternative "
        "exists, and ask upstreams you rely on to adopt Trusted "
        "Publishing with attestations (a one-line change to a GitHub "
        "Actions ``pypa/gh-action-pypi-publish`` job). This is a "
        "posture signal, not a defect in the dependency. The npm "
        "analog is NPM-015."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to read each "
        "direct dependency's latest-release attestation surface from "
        "the PyPI JSON API (the same per-package document the cooldown "
        "/ OSV passes fetch, so it adds no extra requests). Reads the "
        "``provenance`` field on the latest release's file records and "
        "flags a package whose files carry no populated provenance. "
        "Scoped to direct, index-resolved dependencies in the "
        "requirements files; URL / VCS / ``name @ url`` specs and "
        "transitive packages are out of scope.\n\n"
        "LOW severity by design: PEP 740 attestation adoption across "
        "PyPI is still ramping, so the absence is common and this is "
        "an informational posture signal that stays below the default "
        "``--fail-on`` gate. When ``--resolve-remote`` is off, the "
        "registry can't be reached, or the index doesn't expose the "
        "attestation field, the rule passes silently."
    ),
    known_fp=(
        "A distribution can be securely published without PEP 740 "
        "attestations (it may predate Trusted Publishing, or use a "
        "different signing scheme). The absence is a weaker signal "
        "than a present-but-invalid attestation would be. Suppress "
        "per-resource for dependencies whose supply chain the team has "
        "otherwise vetted.",
    ),
    incident_refs=(
        "PEP 740 / PyPI digital attestations (GA November 2024): "
        "publishing via Trusted Publishing produces a signed, "
        "verifiable link from the PyPI artifact to the exact source "
        "commit and CI run, the property an attacker who republishes a "
        "tampered distribution cannot forge.",
    ),
    exploit_example=(
        "# Risk: ``legacy-lib``'s latest release ships no PEP 740\n"
        "# attestation, so there is no signed link from the PyPI\n"
        "# distribution back to a source commit and CI run. A\n"
        "# registry-side tamper or a maintainer-account republish of a\n"
        "# tampered build can't be detected by verifying provenance,\n"
        "# because there is none.\n"
        "# requirements.txt\n"
        "legacy-lib==2.0.0\n"
        "\n"
        "# Surface it: ``pipeline_check --pipeline pypi\n"
        "# --resolve-remote`` reads each direct dependency's\n"
        "# attestation surface from the PyPI JSON API and flags the\n"
        "# ones publishing without provenance, so you can weigh a\n"
        "# provenance-publishing alternative or ask the upstream to\n"
        "# turn on Trusted Publishing.\n"
    ),
)


def check(rf: RequirementsFile, ctx: PypiContext | None = None) -> Finding:
    provenance: dict[str, bool] = ctx.provenance if ctx is not None else {}
    if not provenance:
        # No metadata; silent pass. ``--resolve-remote`` is the opt-in
        # network path; its absence must not fail CI on the default
        # offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "No provenance metadata available (re-run with "
                "``--resolve-remote`` to enable provenance analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for line in iter_specs(rf):
        name = requirement_package_name(line.body)
        if name is None or name in seen:
            continue
        seen.add(name)
        has_prov = provenance.get(name)
        if has_prov is not False:
            # ``True`` (has provenance) or ``None`` (unresolved); skip.
            continue
        offenders.append(name)
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))
    passed = not offenders
    desc = (
        "Every resolved direct dependency publishes with PEP 740 provenance."
        if passed else
        f"{len(offenders)} direct dependency / dependencies publish "
        f"without PEP 740 provenance: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Without an attestation the "
        f"distribution can't be cryptographically traced back to its "
        f"source commit and CI build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
