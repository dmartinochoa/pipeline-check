"""NPM-019, ``overrides`` / ``resolutions`` rewrites a dep to a non-registry source."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest

RULE = Rule(
    id="NPM-019",
    title="package.json overrides / resolutions rewrites a dependency to a non-registry source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Keep ``overrides`` (npm), ``resolutions`` (Yarn), and "
        "``pnpm.overrides`` to exact registry versions. A git / URL / "
        "``file:`` / ``npm:``-alias target in an override force-replaces "
        "the resolved source of a package anywhere in the tree, "
        "including deep transitives, ahead of the lockfile and without "
        "touching any ``dependencies`` line a reviewer reads. If you must "
        "override to a fork, pin it to a 40-character commit SHA and "
        "vendor it into a registry you control; if you must alias a name "
        "(``npm:``), confirm the target package is one you trust, since "
        "the alias silently redirects a trusted name to a different "
        "package."
    ),
    docs_note=(
        "Fires when an ``overrides`` / ``resolutions`` / "
        "``pnpm.overrides`` entry (walked recursively, so nested npm "
        "overrides are covered) resolves a package to a non-registry "
        "source: a git spec (``git+...`` / ``github:`` / ``gitlab:`` / "
        "``bitbucket:``), an ``http(s)://`` tarball, a ``file:`` / "
        "``link:`` / ``portal:`` local path, or an ``npm:<other>`` alias "
        "that redirects the name to a different package. A plain "
        "version / range override (the common, legitimate use, pinning a "
        "transitive to a patched version) passes. Distinct from NPM-001 / "
        "NPM-005, which only walk the ``*dependencies`` blocks via "
        "``iter_manifest_dependencies`` and never read the override map."
    ),
    exploit_example=(
        "// Vulnerable: an override redirects a trusted transitive to an\n"
        "// attacker fork / alias. No ``dependencies`` line changes, so a\n"
        "// reviewer scanning the dependency list sees nothing.\n"
        "// package.json\n"
        "{\n"
        "  \"overrides\": {\n"
        "    \"chalk\": \"npm:chalk-evil@5.0.0\",\n"
        "    \"ansi-styles\": \"git+https://github.com/attacker/ansi-styles.git#main\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Attack: on the next ``npm install`` the whole tree resolves\n"
        "// ``chalk`` to the aliased ``chalk-evil`` package and\n"
        "// ``ansi-styles`` from the attacker's mutable ``#main``, running\n"
        "// their install scripts / shipping their code into the build.\n"
        "\n"
        "// Safe: override only to an exact registry version (a patched\n"
        "// transitive), the legitimate use of the field.\n"
        "// package.json\n"
        "{\n"
        "  \"overrides\": {\n"
        "    \"ansi-styles\": \"6.2.1\"\n"
        "  }\n"
        "}"
    ),
)

# Non-registry target shapes. A git / URL / local-path / alias target
# rewrites WHERE a package comes from, the dependency-confusion /
# source-substitution risk; a bare version or range does not.
_GIT_PREFIXES: tuple[str, ...] = (
    "git+", "git://",
)
_VCS_SHORTHANDS: tuple[str, ...] = (
    "github:", "gitlab:", "bitbucket:", "gist:",
)
_URL_PREFIXES: tuple[str, ...] = (
    "http://", "https://",
)
_LOCAL_PREFIXES: tuple[str, ...] = (
    "file:", "link:", "portal:",
)


def _redirect_kind(spec: str) -> str | None:
    """Classify an override target spec; ``None`` means a safe version/range."""
    s = spec.strip()
    if not s:
        return None
    lowered = s.lower()
    if lowered.startswith(_GIT_PREFIXES) or lowered.startswith(_VCS_SHORTHANDS):
        return "git source"
    if lowered.startswith(_URL_PREFIXES):
        return "remote URL"
    if lowered.startswith(_LOCAL_PREFIXES):
        return "local path"
    if lowered.startswith("npm:"):
        return "npm: alias to a different package"
    return None


def _walk_overrides(
    node: Any, path: str, out: list[tuple[str, str]],
) -> None:
    """Collect ``(label, spec)`` for every string leaf in an override tree.

    npm ``overrides`` nest (``{"foo": {"bar": "1.0.0"}}`` overrides bar
    only under foo; a ``"."`` key targets the parent itself). Yarn
    ``resolutions`` and ``pnpm.overrides`` are flat, which this walk
    handles as the depth-1 case.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            label = path if key == "." else (f"{path} > {key}" if path else key)
            _walk_overrides(value, label, out)
    elif isinstance(node, str):
        out.append((path, node))


def check(manifest: NpmManifest) -> Finding:
    specs: list[tuple[str, str]] = []
    _walk_overrides(manifest.data.get("overrides"), "", specs)
    _walk_overrides(manifest.data.get("resolutions"), "", specs)
    pnpm = manifest.data.get("pnpm")
    if isinstance(pnpm, dict):
        _walk_overrides(pnpm.get("overrides"), "", specs)

    offenders: list[str] = []
    locations: list[Location] = []
    for label, spec in specs:
        kind = _redirect_kind(spec)
        if kind is None:
            continue
        offenders.append(f"{label or '?'} -> {spec} ({kind})")
        idx = manifest.text.find(spec)
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No overrides / resolutions redirect a dependency to a "
        "non-registry source."
        if passed else
        f"{len(offenders)} override(s) rewrite a dependency to a "
        f"non-registry source: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The override applies "
        f"tree-wide (including transitives) ahead of the lockfile, "
        f"with no change to any dependencies line."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
