"""PYPI-021, direct dependency provenance built from a non-release ref.

The PyPI / PEP 740 analog of NPM-017. The consumer-side lesson of the
Red Hat npm compromise (BoostSecurity, "Trusted Publishing, Untrusted
Branch", 2026): the malicious releases carried *valid* build provenance,
just minted from a throwaway ``refs/heads/oidc-b67eedca`` branch. Valid
provenance is not a trusted branch. A dependency whose latest release
was built from a branch that is neither a tag nor the repo's default
branch is worth a second look: a legitimate release is normally cut from
a tag or a protected branch, not an arbitrary one.

Extends PYPI-019's attestation read: PYPI-019 flags the *absence* of a
PEP 740 attestation; PYPI-021 flags a *present* attestation whose SLSA
source ref is suspect. This is the only install-side signal that would
have distinguished the Red Hat-style packages from a legitimate trusted
publish.
"""
from __future__ import annotations

from ..._primitives.provenance_ref import is_untrusted_publish_ref
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PypiContext, RequirementsFile, iter_specs, requirement_package_name

RULE = Rule(
    id="PYPI-021",
    title="Direct dependency provenance built from a non-release ref",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "A package's PEP 740 attestation records the git ref the release "
        "was built from. A latest release built from a throwaway branch "
        "(``refs/heads/oidc-...``) rather than a tag or the default "
        "branch is the 'untrusted branch' signal: valid provenance, "
        "attacker ref. Confirm the upstream cuts releases only from a "
        "tag or a protected branch, and pin to a known-good version if "
        "its latest provenance ref looks unexpected. If the dependency's "
        "real default branch is not ``main`` / ``master`` (e.g. "
        "``develop``), this is a false positive: suppress it per-resource. "
        "The npm analog is NPM-017."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote``. Reads each "
        "direct dependency's latest-release PEP 740 provenance object "
        "from the PyPI integrity endpoint (the URL the JSON API exposes "
        "on each attested file) and parses the SLSA provenance source "
        "ref (``predicate.buildDefinition.externalParameters.workflow."
        "ref``). Flags a ref that is a branch other than "
        "``refs/heads/main`` / ``refs/heads/master``; a tag "
        "(``refs/tags/...``) or a default branch passes. Skips (does not "
        "flag) a package whose latest release has no provenance "
        "(PYPI-019's concern), whose provenance object can't be fetched "
        "or parsed, or whose ref is an unrecognized shape. Scoped to "
        "direct, index-resolved dependencies. Default-branch detection "
        "assumes ``main`` / ``master``; a repo whose default branch is "
        "named otherwise can be flagged (see known_fp). LOW severity / "
        "MEDIUM confidence: a posture signal below the default "
        "``--fail-on`` gate. Passes silently offline."
    ),
    known_fp=(
        "A project whose default branch is not ``main`` / ``master`` "
        "(``develop``, ``trunk``, a ``release/*`` branch) publishes "
        "legitimately from that branch; this rule treats only "
        "``main`` / ``master`` as the trusted default, so other branch "
        "refs are flagged. Suppress per-resource when the upstream's "
        "release branch is known-good. A SLSA v0.2 attestation or a "
        "non-standard layout that doesn't expose the ref at the parsed "
        "path is skipped, not flagged.",
    ),
    incident_refs=(
        "Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, "
        "Untrusted Branch', 2026): 30+ packages shipped valid SLSA "
        "provenance recording a throwaway ``refs/heads/oidc-*`` branch. "
        "The provenance ref is the only install-side signal that would "
        "have distinguished them. The same class of attack applies to "
        "PyPI PEP 740 attestations minted from an attacker-pushed "
        "branch: "
        "https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
    ),
    exploit_example=(
        "# Risk: ``widget``'s latest release ships a valid PEP 740\n"
        "# attestation, but the SLSA provenance records it was built\n"
        "# from ``refs/heads/oidc-b67eedca`` — a throwaway branch, not a\n"
        "# tag or the default branch. The signature verifies; the ref\n"
        "# is the tell that an attacker published from a branch they\n"
        "# pushed a counterfeit workflow to.\n"
        "# requirements.txt\n"
        "widget==3.0.0\n"
        "\n"
        "# Surface it: ``pipeline_check --pipeline pypi\n"
        "# --resolve-remote`` reads each direct dependency's PEP 740\n"
        "# provenance and flags the ones whose source ref is a branch\n"
        "# other than the default, so you can confirm the upstream's\n"
        "# release process before trusting the build.\n"
    ),
)


def check(rf: RequirementsFile, ctx: PypiContext | None = None) -> Finding:
    refs: dict[str, str] = ctx.provenance_ref if ctx is not None else {}
    if not refs:
        # ``--resolve-remote`` is the opt-in network path; its absence
        # must not fail an offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=rf.path,
            description=(
                "No provenance-ref metadata available (re-run with "
                "``--resolve-remote`` to enable provenance-ref analysis)."
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
        ref = refs.get(name)
        if not ref or not is_untrusted_publish_ref(ref):
            continue
        offenders.append(f"{name} ({ref})")
        locations.append(Location(
            path=rf.path, start_line=line.line_no, end_line=line.line_no,
        ))

    passed = not offenders
    desc = (
        "Every resolved direct dependency's build provenance was minted "
        "from a tag or the default branch."
        if passed else
        f"{len(offenders)} direct dependency / dependencies have build "
        f"provenance minted from a non-release branch ref: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Valid provenance from a "
        f"throwaway branch is the 'untrusted branch' signal; confirm the "
        f"upstream's release ref before trusting the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
