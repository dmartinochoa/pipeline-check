"""NPM-011, ``package.json`` ``files`` field would publish secret paths."""
from __future__ import annotations

import json
import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmManifest

RULE = Rule(
    id="NPM-011",
    title="package.json files field includes secret-shaped paths",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-3"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-538", "CWE-200"),
    recommendation=(
        "Remove the secret-shaped entry from ``package.json`` "
        "``files``. If the entry is intentional (e.g., a "
        "``.env.example`` template that ships intentionally),  "
        "rename it to a clearly-not-a-secret form (``env.example``) "
        "before shipping. Then run ``npm pack --dry-run`` and "
        "inspect the printed contents before the next ``npm "
        "publish``; the dry-run output is the ground truth for "
        "what the registry will receive. Any tarball that includes "
        "``.env``, ``.npmrc`` with an ``_authToken`` line, an SSH "
        "private key, or an AWS credentials file effectively "
        "publishes those credentials to every consumer of the "
        "package."
    ),
    docs_note=(
        "Fires when ``package.json`` declares a ``files`` field "
        "(positive-list of paths npm includes in the published "
        "tarball) and at least one entry matches a secret-shaped "
        "pattern:\n\n"
        "* ``.env`` / ``.env.*`` (env files, AWS keys / DB "
        "  passwords)\n"
        "* ``.npmrc`` (npm auth tokens — `_authToken` lines)\n"
        "* ``*.pem`` / ``*.key`` / ``*.crt`` / ``*.p12`` / "
        "  ``*.pfx`` (TLS / signing keys)\n"
        "* ``id_rsa`` / ``id_dsa`` / ``id_ecdsa`` / ``id_ed25519`` "
        "  (SSH private keys)\n"
        "* ``credentials`` / ``credentials.json`` / "
        "  ``.aws/credentials`` (AWS-style credential blobs)\n"
        "* ``.ssh/`` / ``.gnupg/`` (entire credential directories)\n\n"
        "Wildcard-broad entries (``*``, ``**``, ``./``) are NOT "
        "currently flagged — they're too common to triage at "
        "this layer, and the right defense is ``npm pack --dry-"
        "run`` review. NPM-011 is the file-name detector; the "
        "broad-include surface is a separate rule. The ``.env."
        "example`` template form is a documented known FP — name "
        "it ``env.example`` (no leading dot, no ``.env`` prefix) "
        "to dodge the heuristic."
    ),
    known_fp=(
        "Packages that intentionally ship template / example "
        "secret files (``dotenv-cli``, security-tooling packages) "
        "may legitimately include a ``.env.example``. Rename to "
        "``env.example`` to dodge the regex, or suppress on this "
        "specific rule + module name with a one-line rationale.",
    ),
    incident_refs=(
        "Long-running pattern of npm publishes leaking secrets via "
        "the ``files`` field: published packages containing "
        "``.npmrc`` with auth tokens, AWS credentials in ``.env``, "
        "SSH private keys in dotfiles. Socket.dev and ReversingLabs "
        "research catalogs document hundreds of such incidents "
        "across the npm registry.",
    ),
    exploit_example=(
        "// Vulnerable: ``files`` ships ``.env`` into the tarball.\n"
        "// Anyone who installs the package recovers the AWS key.\n"
        "{\n"
        "  \"name\": \"@org/internal-tool\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"files\": [\n"
        "    \"dist/**\",\n"
        "    \".env\",            // <- ships AWS_SECRET_ACCESS_KEY\n"
        "    \"config/*.json\"\n"
        "  ]\n"
        "}\n"
        "\n"
        "// Attack: ``npm pack`` produces a tarball whose root\n"
        "// contains ``.env`` verbatim. ``npm view <pkg> --json``\n"
        "// + ``npm pack`` from any anonymous consumer recovers it.\n"
        "// AWS credential rotation is the only fix; the bytes\n"
        "// have already left the building.\n"
        "\n"
        "// Safe: never list secret-shaped paths. Use BuildKit /\n"
        "// CI-side secret mounts at build time; produce a built\n"
        "// artifact (``dist/``) and ship only that.\n"
        "{\n"
        "  \"name\": \"@org/internal-tool\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"files\": [\n"
        "    \"dist/**\",\n"
        "    \"README.md\"\n"
        "  ]\n"
        "}"
    ),
)


# Categories of secret-shaped patterns. Each tuple is
# ``(regex, short_label)``; the regex matches against a single
# ``files`` entry (normalized to forward-slash). Anchored at start
# of segment so ``src/.env`` matches but ``my.envelope`` doesn't.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # ``.env`` and ``.env.<suffix>``. ``.env.example`` matches too;
    # known FP documented in the recommendation. The ``(?:\.|$)`` tail
    # already covers a bare ``.env``, so no separate ``.env$`` entry.
    (re.compile(r"(?:^|/)\.env(?:\.|$)", re.IGNORECASE), ".env file"),
    # ``.npmrc`` (the npm auth-token file).
    (re.compile(r"(?:^|/)\.npmrc$", re.IGNORECASE), ".npmrc (auth tokens)"),
    # TLS / signing key extensions.
    (re.compile(r"\.(?:pem|key|crt|p12|pfx)$", re.IGNORECASE), "TLS / signing key file"),
    # SSH private keys (canonical id_* filenames).
    # Anchored to exact filename (no ``.pub`` suffix) so public keys
    # are not flagged as secret material.
    (re.compile(r"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$", re.IGNORECASE), "SSH private key"),
    # ``.ssh/`` directory tree.
    (re.compile(r"(?:^|/)\.ssh(?:/|$)", re.IGNORECASE), ".ssh/ directory"),
    # ``.gnupg/`` directory tree.
    (re.compile(r"(?:^|/)\.gnupg(?:/|$)", re.IGNORECASE), ".gnupg/ directory"),
    # AWS-style credential blobs.
    (re.compile(r"(?:^|/)credentials(?:\.json)?$", re.IGNORECASE), "credentials file"),
    (re.compile(r"(?:^|/)\.aws(?:/|$)", re.IGNORECASE), ".aws/ directory"),
)


def _normalize_glob(entry: str) -> str:
    """Normalize backslashes to forward slashes and strip leading ``./``.

    npm accepts both separators on Windows but stores them as posix
    when packing. Normalize so the regex set doesn't need to match
    twice.
    """
    cleaned = entry.replace("\\", "/").strip()
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _classify(entry: str) -> str | None:
    """Return a short label for the secret category matched, or None."""
    cleaned = _normalize_glob(entry)
    for pattern, label in _SECRET_PATTERNS:
        if pattern.search(cleaned):
            return label
    return None


def check(manifest: NpmManifest) -> Finding:
    files = manifest.data.get("files")
    if not isinstance(files, list) or not files:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="package.json declares no ``files`` field.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for entry in files:
        if not isinstance(entry, str):
            continue
        label = _classify(entry)
        if label is None:
            continue
        offenders.append(f"{entry!r}: {label}")
        # Best-effort: locate the entry literal in the source text.
        # ``json.dumps`` re-escapes backslashes / quotes so the
        # search string matches the JSON-encoded representation.
        idx = manifest.text.find(json.dumps(entry))
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "package.json ``files`` field does not list any secret-"
        "shaped path."
        if passed else
        f"{len(offenders)} entry / entries in ``files`` match a "
        f"secret-shaped pattern: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any tarball produced "
        f"by ``npm pack`` includes those bytes; ``npm publish`` "
        f"ships them to every consumer."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
