"""NPM-001, ``package.json`` dependency uses a floating version range."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-001",
    title="package.json dependency uses a floating version range",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace floating range specifiers (``^``, ``~``, ``*``, "
        "``>=``, ``latest``) with an exact version pin (``\"lodash\": "
        "\"4.17.21\"``). The floating form lets npm install any "
        "later version that matches the range, so a compromised "
        "patch release (TanStack, axios, debug, Shai-Hulud) reaches "
        "the build without a code change. Pair the pinned manifest "
        "with a committed ``package-lock.json`` (NPM-002 / NPM-003 "
        "guard the lockfile content)."
    ),
    docs_note=(
        "Fires on every entry in ``dependencies`` / ``devDependencies`` "
        "/ ``optionalDependencies`` / ``peerDependencies`` whose value "
        "starts with ``^``, ``~``, ``*``, ``>``, ``<``, ``||``, carries "
        "a wildcard token (``1.x``, ``1.2.X``, ``x``), or is the "
        "dist-tag ``latest`` / ``next`` / ``beta`` / ``alpha`` / "
        "``canary`` / ``dev``. ``workspace:*`` (Yarn / pnpm workspace "
        "protocol), ``file:`` / ``link:`` (local checkouts), ``git+`` "
        "/ ``http(s)://`` (URL deps), and ``npm:`` (alias) are not "
        "version ranges and are routed to other rules. Complements "
        "NPM-002, which catches lockfile entries missing integrity "
        "hashes; NPM-001 is the manifest-side hygiene."
    ),
    known_fp=(
        "Monorepo packages that pin every dep to a workspace-internal "
        "version often use ``workspace:*``; those are skipped by the "
        "rule. Library packages (``private: false``, ``main`` set) "
        "intentionally use ranges in ``peerDependencies`` so consumers "
        "can satisfy them flexibly; suppress with a one-line rationale "
        "for libraries you publish to npm.",
    ),
    incident_refs=(
        "TanStack / Mistral npm compromise (May 2026): 84 versions "
        "across 42 packages published in minutes, each carrying a "
        "credential-stealing ``postinstall``. Consumers with floating "
        "ranges (``^x.y.z``) installed the poisoned versions on the "
        "next install; pinned exact-version repos were spared until "
        "they manually bumped.",
    ),
)


# Tag-style mutable specifiers commonly accepted by ``npm install``.
_MUTABLE_TAGS: frozenset[str] = frozenset({
    "latest", "next", "beta", "alpha", "canary", "dev", "rc",
})

# Prefixes that explicitly route to other rules (URL / VCS / workspace).
_NON_RANGE_PREFIXES: tuple[str, ...] = (
    "workspace:", "file:", "link:", "portal:", "patch:", "npm:",
    "git+", "git:", "http://", "https://", "github:", "gitlab:",
    "bitbucket:", "gist:",
)

_FLOATING_PREFIX_RE = re.compile(r"^[\^~*><]|^\|\|")
# npm semver wildcard token: a bare ``x`` / ``X`` in one of the
# version-number positions (``1.x``, ``1.2.X``, ``1.x.x``, or bare
# ``x``). Equivalent to a caret range, so floating. Anchored at
# ``.`` boundaries to avoid matching ``alpha.x`` pre-release tails.
_FLOATING_WILDCARD_RE = re.compile(r"(?:^|\.)[xX](?:\.|$)")


def _is_floating(spec: str) -> bool:
    stripped = spec.strip()
    if not stripped:
        return False
    if stripped.startswith(_NON_RANGE_PREFIXES):
        return False
    if stripped.lower() in _MUTABLE_TAGS:
        return True
    if _FLOATING_PREFIX_RE.match(stripped):
        return True
    return bool(_FLOATING_WILDCARD_RE.search(stripped))


def check(manifest: NpmManifest) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for section, name, spec in iter_manifest_dependencies(manifest):
        if not _is_floating(spec):
            continue
        offenders.append(f"{section}.{name}: {spec}")
        # Best-effort line lookup on the quoted dep name.
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every dependency in package.json is pinned to an exact version."
        if passed else
        f"{len(offenders)} dependency / dependencies use a floating "
        f"range: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromised patch "
        f"release reaches the build on the next install without any "
        f"code change."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
