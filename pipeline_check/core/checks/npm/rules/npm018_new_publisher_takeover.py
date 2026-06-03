"""NPM-018, direct dependency's latest release came from a new publisher."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-018",
    title="Direct dependency's latest release published by a new npm account",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Treat a publisher change as the live account-takeover signal it "
        "is: the latest release of this dependency was published by an "
        "npm account that published none of its earlier versions. That is "
        "exactly the shape of a stolen-credential or freshly-added-account "
        "compromise (the axios / @ctrl/tinycolor / chalk class), where an "
        "attacker pushes one malicious release that every consumer pulls "
        "on the next install. Before upgrading into the new release: "
        "confirm the maintainer change is legitimate (a documented "
        "hand-off, a new co-maintainer the project announced), pin to the "
        "last release from the known publisher until you have, and pair "
        "with NPM-008 (cooldown) so a hijacked release has a window to be "
        "caught before it reaches your lockfile. NPM-014 (single "
        "publisher) is the standing blast-radius; this is the moment that "
        "blast radius fires."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to read each "
        "direct dependency's per-version publisher (the packument's "
        "``_npmUser`` account that ran ``npm publish`` for each version, "
        "from the same fetch NPM-008 / NPM-014 use, so it adds no extra "
        "requests). Flags a package whose ``dist-tags.latest`` version "
        "was published by an account that published none of its prior "
        "versions. Requires at least three prior versions with a known "
        "publisher, so a brand-new package (one or two releases, where a "
        "\"new publisher\" is meaningless and NPM-008's cooldown already "
        "covers the fresh-carrier risk) is skipped. Scoped to direct "
        "dependencies in ``dependencies`` / ``devDependencies`` / "
        "``optionalDependencies`` / ``peerDependencies``; transitive "
        "packages are out of scope. MEDIUM confidence: a legitimate new "
        "co-maintainer's first publish trips it too, so the finding is a "
        "review prompt rather than proof of compromise. When "
        "``--resolve-remote`` is off, the registry can't be reached, or "
        "the packument doesn't expose ``_npmUser``, the rule passes "
        "silently."
    ),
    known_fp=(
        "A legitimate maintainer hand-off or a newly added co-maintainer "
        "publishing their first release flags identically to a takeover "
        "(the per-version publisher is the only static signal; intent "
        "isn't visible). When the change is verified and expected, "
        "suppress per-resource for that dependency.",
    ),
    incident_refs=(
        "axios maintainer-account takeover (March 30, 2026): a "
        "compromised publisher account pushed a malicious release to "
        "~99M weekly downloads, the new-publisher-on-an-established-"
        "package shape this rule surfaces.",
        "@ctrl/tinycolor account takeover (May 2024): a hijacked account "
        "published malicious versions that stayed live for ~36 hours.",
    ),
    exploit_example=(
        "// Risk: ``shiny-lib`` shipped 1.0.0 through 4.1.0 all published\n"
        "// by the npm account `alice`. The latest release, 4.2.0, was\n"
        "// published by `mallory` — an account that published none of\n"
        "// the prior versions. That is the account-takeover fingerprint:\n"
        "// one new publisher, one fresh release, every consumer pulling\n"
        "// it on the next install.\n"
        "// package.json\n"
        "{\n"
        "  \"dependencies\": {\n"
        "    \"shiny-lib\": \"^4.2.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Surface it: ``pipeline_check --pipeline npm --resolve-remote``\n"
        "// reads each release's publisher from the registry and flags the\n"
        "// dependencies whose latest release came from a new account, so\n"
        "// you can verify the hand-off (or hold at the last known-good\n"
        "// publisher's release) before it lands in your lockfile.\n"
    ),
)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    new_publisher: dict[str, bool] = (
        ctx.new_publisher if ctx is not None else {}
    )
    if not new_publisher:
        # No metadata — silent pass. ``--resolve-remote`` is the opt-in
        # network path (documented in docs_note); the absence of it must
        # not fail CI for users on the default offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No publisher-history metadata available (re-run with "
                "``--resolve-remote`` to enable publisher-change "
                "analysis)."
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
        if not new_publisher.get(name):
            continue  # unresolved, or latest came from an established publisher
        offenders.append(f"{section}.{name}")
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))

    passed = not offenders
    desc = (
        "No direct dependency's latest release came from a new publisher."
        if passed else
        f"{len(offenders)} direct dependency / dependencies had their "
        f"latest release published by an npm account new to the package: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A publisher change on an "
        f"established package is the account-takeover signal; confirm the "
        f"hand-off is legitimate before upgrading."
    )
    # MEDIUM confidence comes from the central _confidence.py registry
    # (the legit-new-maintainer FP mode); the rule doesn't set it inline.
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
