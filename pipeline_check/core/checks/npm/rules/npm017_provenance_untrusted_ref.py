"""NPM-017, direct dependency provenance built from a non-release ref.

The consumer-side lesson of the Red Hat npm compromise (BoostSecurity,
"Trusted Publishing, Untrusted Branch", 2026): the malicious releases
carried *valid* SLSA build provenance, just minted from a throwaway
``refs/heads/oidc-b67eedca`` branch. Valid provenance is not a trusted
branch. A dependency whose latest release was built from a branch that
is neither a tag nor the repo's default branch is worth a second look:
a legitimate release is normally cut from a tag or a protected branch,
not an arbitrary one.

Extends NPM-015's attestation read: NPM-015 flags the *absence* of
provenance; NPM-017 flags a *present* provenance whose source ref is
suspect. This is the only signal that would have flagged the Red Hat
packages on the install side. PYPI-021 is the PyPI / PEP 740 analog.
"""
from __future__ import annotations

from ..._primitives.provenance_ref import is_untrusted_publish_ref
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-017",
    title="Direct dependency provenance built from a non-release ref",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "A package's build provenance records the git ref the release "
        "was built from. A latest release built from a throwaway branch "
        "(``refs/heads/oidc-...``) rather than a tag or the default "
        "branch is the 'untrusted branch' signal: valid provenance, "
        "attacker ref. Confirm the upstream cuts releases only from a "
        "tag or a protected branch, and pin to a known-good version if "
        "its latest provenance ref looks unexpected. If the dependency's "
        "real default branch is not ``main`` / ``master`` (e.g. "
        "``develop``), this is a false positive: suppress it per-resource."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote``. Reads each "
        "direct dependency's latest-version attestation bundle from "
        "``registry.npmjs.org/-/npm/v1/attestations`` and parses the "
        "SLSA provenance source ref (``predicate.buildDefinition."
        "externalParameters.workflow.ref``). Flags a ref that is a "
        "branch other than ``refs/heads/main`` / ``refs/heads/master``; "
        "a tag (``refs/tags/...``) or a default branch passes. Skips "
        "(does not flag) a package whose latest version has no "
        "provenance (NPM-015's concern), whose attestation can't be "
        "fetched or parsed, or whose ref is an unrecognized shape. "
        "Scoped to direct dependencies. Default-branch detection assumes "
        "``main`` / ``master``; a repo whose default branch is named "
        "otherwise can be flagged (see known_fp). LOW severity / MEDIUM "
        "confidence: a posture signal below the default ``--fail-on`` "
        "gate. Passes silently offline."
    ),
    known_fp=(
        "A project whose default branch is not ``main`` / ``master`` "
        "(``develop``, ``trunk``, a ``release/*`` branch) publishes "
        "legitimately from that branch; this rule treats only "
        "``main`` / ``master`` as the trusted default, so other branch "
        "refs are flagged. Suppress per-resource when the upstream's "
        "release branch is known-good. A monorepo or non-standard SLSA "
        "layout that doesn't expose the ref at the parsed path is "
        "skipped, not flagged.",
    ),
    incident_refs=(
        "Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, "
        "Untrusted Branch', 2026): 30+ packages shipped valid SLSA "
        "provenance recording a throwaway ``refs/heads/oidc-*`` branch. "
        "The provenance ref is the only install-side signal that would "
        "have distinguished them: "
        "https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
    ),
    exploit_example=(
        "// Risk: ``widget``'s latest release ships valid build\n"
        "// provenance, but the provenance records it was built from\n"
        "// ``refs/heads/oidc-b67eedca`` — a throwaway branch, not a\n"
        "// tag or the default branch. The signature verifies; the ref\n"
        "// is the tell that an attacker published from a branch they\n"
        "// pushed a counterfeit workflow to.\n"
        "// package.json\n"
        "{\n"
        "  \"dependencies\": {\n"
        "    \"widget\": \"^3.0.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Surface it: ``pipeline_check --pipeline npm\n"
        "// --resolve-remote`` reads each direct dependency's provenance\n"
        "// attestation and flags the ones whose source ref is a branch\n"
        "// other than the default, so you can confirm the upstream's\n"
        "// release process before trusting the build.\n"
    ),
)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    refs: dict[str, str] = ctx.provenance_ref if ctx is not None else {}
    if not refs:
        # ``--resolve-remote`` is the opt-in network path; its absence
        # must not fail an offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No provenance-ref metadata available (re-run with "
                "``--resolve-remote`` to enable provenance-ref analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for section, name, _spec in iter_manifest_dependencies(manifest):
        if name in seen:
            continue
        seen.add(name)
        ref = refs.get(name)
        if not ref or not is_untrusted_publish_ref(ref):
            continue
        offenders.append(f"{section}.{name} ({ref})")
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
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
        f"throwaway branch is the npm 'untrusted branch' signal; confirm "
        f"the upstream's release ref before trusting the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
