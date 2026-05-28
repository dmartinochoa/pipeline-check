"""COMPOSER-004. Repository URL embeds plaintext credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-004",
    title="composer.json repository URL embeds plaintext credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Move credentials out of ``composer.json`` and into "
        "``auth.json`` (or the equivalent environment "
        "variables: ``COMPOSER_AUTH``). ``auth.json`` is "
        "git-ignored by Composer convention; "
        "``COMPOSER_AUTH`` reads JSON from the environment so "
        "the runner can mount the secret out-of-band. The URL "
        "in composer.json should be just the host and path "
        "with no userinfo. After scrubbing the manifest, "
        "rotate the credential — anything that was committed "
        "to git is compromised."
    ),
    docs_note=(
        "Fires when a repository ``url`` value parses to a "
        "userinfo segment (``https://user:pass@host/...``) and "
        "the password segment is not a Composer / "
        "shell-expansion placeholder ("
        "``${COMPOSER_AUTH_TOKEN}`` / ``%env(...)%``). Common "
        "case: copy-pasted setup script from a tutorial that "
        "embedded the token literally."
    ),
    known_fp=(
        "URLs that embed only a username (``https://"
        "deploy@host/...``) for OAuth-style flows without a "
        "literal secret. The rule allows usernames; only "
        "user:password pairs trip it.",
    ),
    incident_refs=(
        "Standing-up a private Composer mirror and "
        "copy-pasting the bootstrap URL straight into "
        "composer.json is a well-trodden footgun; the "
        "credential lands in git history and is then exposed "
        "to anyone who can read the repo.",
    ),
    exploit_example=(
        "// Vulnerable: token in the manifest URL.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"composer\",\n"
        "      \"url\": \"https://bot:s3cr3t@nexus.corp/composer\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "\n"
        "// Safe: scrub manifest, move to auth.json.\n"
        "// composer.json:\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"composer\",\n"
        "      \"url\": \"https://nexus.corp/composer\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "// auth.json (gitignored):\n"
        "{\n"
        "  \"http-basic\": {\n"
        "    \"nexus.corp\": {\n"
        "      \"username\": \"bot\",\n"
        "      \"password\": \"s3cr3t\"\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


# Match ``scheme://user:password@host`` where ``password`` is one or
# more characters that are not ``$``, ``%``, ``{``, ``}`` (i.e. not
# an obvious placeholder expression).
_CREDS_RE = re.compile(
    r"^[a-z][a-z0-9+\-.]*://[^:/@?\s]+:([^@/\s]+)@",
    re.IGNORECASE,
)


def _is_placeholder(secret: str) -> bool:
    s = secret.strip()
    if not s:
        return True
    placeholder_markers = ("${", "%env(", "%(", "{{", "$(", "<")
    return any(m in s for m in placeholder_markers)


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        url = repo.url
        if not url:
            continue
        m = _CREDS_RE.match(url)
        if not m:
            continue
        if _is_placeholder(m.group(1)):
            continue
        # Redact the secret in the rendered output so the finding
        # doesn't expand the blast radius further.
        offenders.append((repo.type, _CREDS_RE.sub(
            lambda mm: mm.group(0)[: mm.start(1) - mm.start(0)]
            + "***@", url,
        )))
        locations.append(Location(
            path=pom.path,
            start_line=repo.line_no, end_line=repo.line_no,
        ))
    passed = not offenders
    if passed:
        desc = "No repository URL embeds plaintext credentials."
    else:
        rendered = ", ".join(
            f"{rtype}:{url}" for rtype, url in offenders[:3]
        )
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} repository URL / URLs embed "
            f"plaintext credentials: {rendered}{suffix}. Move "
            f"the secret to auth.json or $COMPOSER_AUTH and "
            f"rotate it."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
