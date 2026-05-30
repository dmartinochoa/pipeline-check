"""GEM-013. Gemfile git / github gem fetched over an insecure transport."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-013",
    title="Gemfile git gem fetched over an insecure transport",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319", "CWE-829"),
    recommendation=(
        "Clone every ``git:`` gem over an authenticated, encrypted "
        "transport (``https://`` or ``ssh://`` / ``git@``). The "
        "``git://`` protocol carries no encryption and no server "
        "authentication, and a plain ``http://`` clone is equally "
        "open to a MITM swapping the cloned tree, so an attacker on "
        "the network path between the runner and the host can serve "
        "a backdoored repository. (GitHub removed ``git://`` "
        "support entirely in 2022 for exactly this reason.) Switch "
        "the URL to ``https://`` and pair it with a ``ref:`` SHA "
        "pin (GEM-005) so both the channel and the content are "
        "verifiable."
    ),
    docs_note=(
        "Fires on a ``gem`` entry whose ``git:`` URL uses the "
        "``git://`` protocol or a plain ``http://`` clone URL. The "
        "``github:`` shorthand resolves to HTTPS and is not "
        "flagged; ``https://``, ``ssh://``, and ``git@host:`` "
        "forms pass. Companion to GEM-003 (a registry ``source`` "
        "over HTTP) and GEM-005 (a git source missing a ref pin), "
        "covering the git-transport gap neither one sees."
    ),
    known_fp=(
        "Air-gapped internal git mirrors on a trusted network "
        "segment may serve plain ``git://`` / ``http://``. Suppress "
        "per line with a rationale naming the network boundary; "
        "better, front the mirror with an HTTPS or SSH endpoint.",
    ),
    incident_refs=(
        "The unauthenticated ``git://`` protocol is a textbook MITM "
        "surface: GitHub deprecated and then disabled it in 2022 "
        "because a network attacker could serve arbitrary repository "
        "content over the unprotected channel.",
    ),
    exploit_example=(
        "# Vulnerable: unauthenticated git:// transport.\n"
        "gem \"some-gem\", git: \"git://example.com/org/some-gem\"\n"
        "gem \"other\", git: \"http://internal/repos/other\", "
        "ref: \"a1b2c3d\"\n"
        "\n"
        "# Attack: a MITM on the path to example.com answers the\n"
        "# clone with a backdoored tree. git:// has no server auth\n"
        "# and no encryption, so nothing detects the swap; even a\n"
        "# ref: pin only fixes the content the attacker chooses to\n"
        "# serve under that SHA's name on an unauthenticated channel.\n"
        "\n"
        "# Safe: HTTPS transport + SHA pin.\n"
        "gem \"some-gem\", "
        "git: \"https://example.com/org/some-gem\", "
        "ref: \"a1b2c3d4e5f6...\""
    ),
)


_INSECURE_PREFIXES: tuple[str, ...] = ("git://", "http://")


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.is_git or not dep.git_url:
            continue
        url = dep.git_url
        # The ``github:`` shorthand is synthesized as ``github:owner/repo``
        # and always resolves to HTTPS; never insecure.
        if url.startswith("github:"):
            continue
        if url.lower().startswith(_INSECURE_PREFIXES):
            offenders.append(f"{dep.name}@{url}")
            locations.append(Location(
                path=pom.path,
                start_line=dep.line_no, end_line=dep.line_no,
            ))
    passed = not offenders
    desc = (
        "All git gem sources use an encrypted, authenticated transport."
        if passed else
        f"{len(offenders)} git gem source(s) use an insecure "
        f"transport: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. git:// and http:// "
        f"clones have no server authentication; a MITM can serve a "
        f"backdoored tree. Switch to https:// or ssh://."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
