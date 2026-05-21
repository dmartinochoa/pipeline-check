"""NPM-003, ``package-lock.json`` entry resolves from a non-registry source."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmLock, iter_lock_packages

RULE = Rule(
    id="NPM-003",
    title="package-lock.json entry resolves from a non-registry source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Move the dependency to a hash-verifiable registry source. "
        "If you genuinely need a fork that's not on npm, pin it via "
        "``git+https://host/owner/repo.git#<40-char-sha>`` (exact "
        "commit, not a branch or tag) and document the audit trail. "
        "``git+ssh://`` URLs are unreviewable by anyone without "
        "access to the same private SSH endpoint; ``http://`` URLs "
        "are MITM-able; bare ``file:`` paths bind the build to a "
        "developer-machine layout. The default-safe shape is "
        "``https://registry.npmjs.org/...`` with ``integrity: "
        "sha512-...``, anything else needs a one-line rationale."
    ),
    docs_note=(
        "Fires when a lockfile entry's ``resolved`` URL points at "
        "anything other than an HTTPS registry. Detected shapes:\n\n"
        "* ``git+ssh://`` / ``ssh://`` — opaque, unreviewable\n"
        "* ``git+http://`` / ``git://`` / ``http://`` — unencrypted "
        "transport, MITM surface\n"
        "* ``file:`` referencing anything outside the project tree — "
        "host-specific install\n\n"
        "Standard ``https://registry.npmjs.org`` and other registered "
        "registries (GitHub Packages, Verdaccio, internal proxies) "
        "pass. A ``git+https://`` URL with a 40-character SHA also "
        "passes — that's the documented escape hatch for forks not "
        "yet published to a registry. Complements NPM-002 (missing "
        "integrity hash); NPM-003 catches the *source* shape, NPM-"
        "002 catches the *verification* shape."
    ),
    exploit_example=(
        "// Vulnerable: ``resolved`` URL is git+ssh — a fork pulled\n"
        "// from an upstream the team can't audit publicly. The\n"
        "// branch ``@main`` is mutable; whoever can push to the\n"
        "// upstream ships code into every consumer's build.\n"
        "// package-lock.json\n"
        "{\n"
        "  \"packages\": {\n"
        "    \"node_modules/internal-fork\": {\n"
        "      \"version\": \"1.0.0\",\n"
        "      \"resolved\": \"git+ssh://git@github.com/myorg/upstream-fork.git#main\"\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: publish the fork to a registry you control (GitHub\n"
        "// Packages, Verdaccio, npm scoped package) and pin via\n"
        "// version + integrity. If the upstream truly can't move,\n"
        "// pin via ``git+https://...#<40-char-sha>`` so the git\n"
        "// object is immutable.\n"
        "// package-lock.json\n"
        "{\n"
        "  \"packages\": {\n"
        "    \"node_modules/internal-fork\": {\n"
        "      \"version\": \"1.0.0\",\n"
        "      \"resolved\": \"https://npm.pkg.github.com/myorg/internal-fork/-/internal-fork-1.0.0.tgz\",\n"
        "      \"integrity\": \"sha512-abc123...==\"\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


# A 40-hex-char commit SHA after ``#`` in a ``git+https://`` URL is
# the only acceptable pinning shape for VCS deps.
_GIT_SHA_PIN_RE = re.compile(r"#[0-9a-f]{40}(?:\Z|[?&])", re.IGNORECASE)

# Unsafe transport shapes for ``resolved``.
_UNSAFE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("git+ssh://", "git+ssh (opaque transport)"),
    ("ssh://", "ssh (opaque transport)"),
    ("git+http://", "git+http (unencrypted)"),
    ("git://", "git:// (unencrypted)"),
    ("http://", "http (unencrypted)"),
)


def _classify(resolved: str) -> str | None:
    """Return a short label for the unsafe shape, or ``None`` if safe."""
    lowered = resolved.strip().lower()
    if not lowered:
        return None
    for prefix, label in _UNSAFE_PREFIXES:
        if lowered.startswith(prefix):
            return label
    if lowered.startswith("git+https://"):
        # Acceptable only with a 40-char SHA pin.
        if not _GIT_SHA_PIN_RE.search(resolved):
            return "git+https without 40-char commit SHA pin"
        return None
    if lowered.startswith("file:"):
        # A relative ``file:./packages/foo`` is fine in a monorepo
        # (the path stays inside the tree); flag absolute / parent-
        # traversal forms.
        rest = resolved[len("file:"):]
        if rest.startswith(("/", "~", "../", "..\\")) or ":" in rest[:3]:
            return "file: source outside project tree"
        return None
    return None


def check(lock: NpmLock) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for install_path, record in iter_lock_packages(lock):
        resolved = record.get("resolved")
        if not isinstance(resolved, str):
            continue
        label = _classify(resolved)
        if label is None:
            continue
        offenders.append(f"{install_path}: {label}")
        idx = lock.text.find(f'"{install_path}"')
        line_no = lock.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=lock.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every lockfile entry resolves from a hash-verifiable HTTPS "
        "registry source."
        if passed else
        f"{len(offenders)} lockfile entries resolve from a non-"
        f"registry source: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any source that "
        f"isn't an HTTPS registry with an integrity hash is opaque "
        f"to verification on the next install."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=lock.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
