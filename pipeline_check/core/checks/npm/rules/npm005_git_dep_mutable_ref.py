"""NPM-005, ``package.json`` git dependency uses a mutable ref."""
from __future__ import annotations

from ..._primitives.sha_ref import SHA_RE_IGNORECASE as _SHA_RE
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-005",
    title="package.json git dependency uses a mutable ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Pin the git dependency to a 40-character commit SHA: "
        "``\"foo\": \"git+https://github.com/owner/repo.git#"
        "<sha>\"``. Branch refs (``#main``, ``#master``) and tag "
        "refs (``#v1.2.3``) are mutable, anyone with push access "
        "to the upstream repo can swap the contents of what your "
        "build pulls without changing the dependency string. A "
        "commit SHA is immutable; a tampered upstream cannot "
        "redirect ``#<sha>`` to different content. If the upstream "
        "isn't yours, vendor the fork into a registry you control "
        "(GitHub Packages, internal Verdaccio) and pin via "
        "registry version instead."
    ),
    docs_note=(
        "Fires on dependency specs of the shapes:\n\n"
        "* ``git+https://host/owner/repo.git#<ref>`` where ``<ref>`` "
        "is not a 40-character SHA\n"
        "* ``github:owner/repo#<ref>`` (shorthand) with non-SHA ``<ref>``\n"
        "* ``git+ssh://...``, ``git://...`` (these are also caught "
        "by NPM-003 on the lockfile side; flagging here gives users "
        "the manifest-side signal too)\n"
        "* A bare ``github:owner/repo`` with no ``#`` ref at all (resolves "
        "to ``HEAD`` of the default branch — fully mutable)\n\n"
        "Skips entries already routed elsewhere: registry specs "
        "(NPM-001), ``file:`` / ``link:`` / ``workspace:`` (NPM-003)."
    ),
)


_GIT_PREFIXES: tuple[str, ...] = (
    "git+https://", "git+http://", "git+ssh://", "git://", "git+",
)
_VCS_SHORTHANDS: tuple[str, ...] = (
    "github:", "gitlab:", "bitbucket:", "gist:",
)


def _is_git_spec(spec: str) -> bool:
    lowered = spec.strip().lower()
    if lowered.startswith(_GIT_PREFIXES):
        return True
    if lowered.startswith(_VCS_SHORTHANDS):
        return True
    return False


def _ref_after_hash(spec: str) -> str | None:
    if "#" not in spec:
        return None
    return spec.split("#", 1)[1].split("&", 1)[0]


def check(manifest: NpmManifest) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for section, name, spec in iter_manifest_dependencies(manifest):
        if not _is_git_spec(spec):
            continue
        ref = _ref_after_hash(spec)
        if ref is None:
            # Bare ``github:owner/repo`` with no ref → HEAD of default
            # branch, the most mutable form there is.
            offenders.append(f"{section}.{name}: {spec} (no ref pin)")
        elif not _SHA_RE.match(ref):
            offenders.append(f"{section}.{name}: {spec} (ref {ref!r} is not a SHA)")
        else:
            continue
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every git dependency in package.json pins a 40-character "
        "commit SHA."
        if passed else
        f"{len(offenders)} git dependency / dependencies use a "
        f"mutable ref: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anyone with push "
        f"access to the upstream can swap the contents without "
        f"changing the dependency string."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
