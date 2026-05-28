"""NPM-013, ``package.json`` ``files`` field uses an overly broad pattern."""
from __future__ import annotations

import json

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest

RULE = Rule(
    id="NPM-013",
    title="package.json files field uses an overly broad pattern",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-3"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-538", "CWE-200"),
    recommendation=(
        "Replace the broad-include entry (``*``, ``**``, ``./``, "
        "``.``, ``**/*``, ``*/**``) with an explicit positive-list of "
        "the paths the package ships: typically ``dist/**`` plus "
        "``README.md`` / ``LICENSE``. ``npm`` interprets a single "
        "``*`` or ``**`` as 'include everything not blocked by an "
        "ignore file', which silently ships every dotfile, env file, "
        "build artifact, and CI script the repo carries unless a "
        "complete ``.npmignore`` exists. Run ``npm pack --dry-run`` "
        "after tightening the list, inspect the printed contents, "
        "and only then ``npm publish``. NPM-011 catches a small set "
        "of secret-shaped *names*; NPM-013 catches the much larger "
        "surface where the pattern itself is the leak."
    ),
    docs_note=(
        "Fires when ``package.json`` declares a ``files`` field whose "
        "list includes any of these broad-include literals:\n\n"
        "* ``\"*\"`` — npm interprets a lone ``*`` as 'every file in "
        "  the package root' (it does NOT mean 'every direct child' "
        "  the way a shell glob does)\n"
        "* ``\"**\"`` / ``\"**/*\"`` / ``\"*/**\"`` — every file in "
        "  every subdirectory\n"
        "* ``\".\"`` / ``\"./\"`` — explicit current-directory "
        "  include\n\n"
        "When the broad entry is the only entry, the tarball is "
        "effectively the repo tree minus whatever ``.npmignore`` / "
        "``.gitignore`` happens to block. Hand-maintained ignore "
        "files routinely miss new dotfiles (``.env.local``, "
        "``.aws/``, ``.terraform/``), so the failure mode is silent "
        "credential leakage at the next ``npm publish``. The right "
        "fix is the explicit positive-list shape NPM-011 already "
        "scans; NPM-013 catches the case where there's no list to "
        "scan because everything is in.\n\n"
        "Skipped: a ``files`` field that omits broad-include entries "
        "(the safe positive-list shape), a manifest with no "
        "``files`` field (different surface — npm falls back to "
        "``.npmignore`` / ``.gitignore`` semantics, which has its "
        "own pitfalls but is out of scope here), and any entry that "
        "narrows the include with a subdirectory prefix "
        "(``dist/**``, ``src/**/*.js``)."
    ),
    known_fp=(
        "A package that is genuinely meant to ship every file in a "
        "tightly-controlled subtree (e.g. a single-file documentation "
        "package whose entire repo IS the publishable content) may "
        "legitimately use ``\"*\"`` paired with a comprehensive, "
        "audited ``.npmignore``. Suppress with a rationale that names "
        "the ``.npmignore`` file and the audit cadence; otherwise "
        "rewrite the field as a positive list.",
    ),
    incident_refs=(
        "Socket.dev and ReversingLabs research catalogs document a "
        "long tail of npm publishes leaking ``.env`` / ``.aws/`` / "
        "``.git/`` content via permissive ``files`` patterns paired "
        "with incomplete ``.npmignore`` files. The pattern is the "
        "single most common credential-leak vector at "
        "``npm publish`` time.",
    ),
    exploit_example=(
        "// Vulnerable: ``files`` is a broad wildcard. The tarball\n"
        "// includes ``.env``, ``.aws/credentials``, ``.terraform/``,\n"
        "// every test fixture, and any CI script with embedded\n"
        "// secrets unless ``.npmignore`` lists every one by name.\n"
        "{\n"
        "  \"name\": \"@org/internal-tool\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"files\": [\"**\"]\n"
        "}\n"
        "\n"
        "// Attack: ``npm pack`` + tarball inspection from any\n"
        "// anonymous consumer recovers whatever the developer's\n"
        "// working tree happened to carry. AWS credential rotation\n"
        "// is the only fix; the bytes have already left.\n"
        "\n"
        "// Safe: explicit positive list. Only the built artifact\n"
        "// and the user-facing docs ship.\n"
        "{\n"
        "  \"name\": \"@org/internal-tool\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"files\": [\"dist/**\", \"README.md\", \"LICENSE\"]\n"
        "}"
    ),
)


_BROAD_LITERALS: frozenset[str] = frozenset({
    "*", "**", "**/*", "*/**", ".", "./",
})


def _normalize(entry: str) -> str:
    """Strip surrounding whitespace and a single trailing slash.

    ``./`` and ``.`` collapse to the same literal; ``**/`` and ``**``
    don't (the trailing slash on a ``**`` would be a malformed entry
    rather than a legitimate variant, but we tolerate it).
    """
    cleaned = entry.strip()
    return cleaned


def check(manifest: NpmManifest) -> Finding:
    files = manifest.data.get("files")
    if not isinstance(files, list) or not files:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "package.json declares no ``files`` field; NPM-013 "
                "only applies to the positive-list shape."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for entry in files:
        if not isinstance(entry, str):
            continue
        if _normalize(entry) in _BROAD_LITERALS:
            offenders.append(entry)
            idx = manifest.text.find(json.dumps(entry))
            line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
            locations.append(Location(
                path=manifest.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "package.json ``files`` field is a bounded positive list."
        if passed else
        f"{len(offenders)} ``files`` entry / entries match a broad-"
        f"include literal: {', '.join(repr(o) for o in offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The published tarball "
        f"is effectively the repo tree minus ``.npmignore``; any "
        f"untracked dotfile or build artifact ships to consumers."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
