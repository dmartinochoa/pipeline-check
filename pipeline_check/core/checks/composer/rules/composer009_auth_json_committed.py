"""COMPOSER-009. auth.json sibling committed with literal credentials."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-009",
    title="auth.json committed alongside composer.json with literal credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-538"),
    recommendation=(
        "Remove ``auth.json`` from version control and add it "
        "to ``.gitignore``. Composer reads credentials from "
        "``auth.json`` out of band of ``composer.json`` for "
        "exactly the reason that the credential should never "
        "live in the same git history as the manifest — the "
        "manifest is meant for the team, ``auth.json`` is meant "
        "for the runner. On CI, export the credential through "
        "``$COMPOSER_AUTH`` (Composer reads JSON-shaped env at "
        "install time) so the runner mounts the secret "
        "out-of-band and no committed file ever holds it.\n\n"
        "After removing the file from the working tree, rotate "
        "every credential the file ever contained. ``git "
        "filter-repo`` (or ``git rebase -i`` for a recent "
        "commit) can remove the file from history, but rotation "
        "is the irrevocable step — anyone who cloned the repo "
        "while the file was tracked has the credential."
    ),
    docs_note=(
        "Fires when the manifest's directory has a sibling "
        "``auth.json`` file and that file's JSON body has at "
        "least one entry under ``http-basic`` / ``bearer`` / "
        "``github-oauth`` / ``gitlab-oauth`` / ``gitlab-token`` "
        "/ ``bitbucket-oauth`` with a literal credential. "
        "Placeholder values "
        "(``${ENV}`` / ``${COMPOSER_AUTH_TOKEN}``) are ignored. "
        "An empty / malformed auth.json passes silently."
    ),
    known_fp=(
        "Some monorepos use a per-project auth.json that "
        "intentionally pins to a low-privilege read-only token "
        "scoped to a single private mirror. The rule still "
        "fires — suppress per file with a one-line rationale "
        "naming the read-only-scope guarantee. Better: move "
        "the credential to a runner-side mount.",
    ),
    incident_refs=(
        "Recurring pattern across PHP shops: a developer "
        "copy-pastes ``composer config http-basic …`` from "
        "internal docs without running ``composer config "
        "--global``, leaving the credential in the project's "
        "``auth.json`` instead of the user's home dir. The "
        "credential then lands in the next commit and is "
        "exposed to every reader of the repo.",
    ),
    exploit_example=(
        "// Vulnerable: auth.json committed next to composer.json.\n"
        "// $ ls\n"
        "// composer.json  composer.lock  auth.json\n"
        "// $ cat auth.json\n"
        "{\n"
        "  \"http-basic\": {\n"
        "    \"nexus.corp\": {\n"
        "      \"username\": \"bot\",\n"
        "      \"password\": \"s3cr3t\"\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: gitignore the file, mount on the runner.\n"
        "// .gitignore:\n"
        "auth.json\n"
        "// CI step:\n"
        "export COMPOSER_AUTH='{\"http-basic\":{\"nexus.corp\":"
        "{\"username\":\"bot\",\"password\":\"$NEXUS_TOKEN\"}}}'"
    ),
)


_CREDENTIAL_KEYS: tuple[str, ...] = (
    "http-basic",
    "bearer",
    "github-oauth",
    "gitlab-oauth",
    "gitlab-token",
    "bitbucket-oauth",
)


def _is_placeholder(value: Any) -> bool:
    """``True`` when ``value`` looks like a shell-expansion / Composer-
    template placeholder rather than a literal credential."""
    if not isinstance(value, str):
        return True
    s = value.strip()
    if not s:
        return True
    return any(m in s for m in (
        "${", "%env(", "%(", "{{", "<", "${{",
    ))


def _section_has_literal(section: Any) -> bool:
    """Walk one auth.json section and return ``True`` if it carries
    at least one literal (non-placeholder) credential value."""
    if isinstance(section, str):
        # Sections like ``bearer`` / ``github-oauth`` may hold a flat
        # ``host: token`` map where the value *is* the credential.
        return not _is_placeholder(section)
    if not isinstance(section, dict):
        return False
    for value in section.values():
        if isinstance(value, str):
            if not _is_placeholder(value):
                return True
        elif isinstance(value, dict):
            # ``http-basic`` entries are ``host: {username, password}``.
            pwd = value.get("password")
            if pwd is not None and not _is_placeholder(pwd):
                return True
    return False


def check(pom: ComposerFile) -> Finding:
    if not pom.auth_json_path:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "No auth.json sibling found next to composer.json."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    for key in _CREDENTIAL_KEYS:
        section = pom.auth_json.get(key)
        if section is None:
            continue
        if _section_has_literal(section):
            offenders.append(key)

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.auth_json_path,
            description=(
                f"auth.json present at ``{pom.auth_json_path}`` but "
                "carries no literal credential values."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    rendered = ", ".join(offenders[:5])
    suffix = "…" if len(offenders) > 5 else ""
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.auth_json_path,
        description=(
            f"auth.json committed at ``{pom.auth_json_path}`` "
            f"carries literal credentials under "
            f"{rendered}{suffix}. Move the file to .gitignore, "
            f"mount via $COMPOSER_AUTH on the runner, and rotate "
            f"every secret the file ever held."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=[Location(
            path=pom.auth_json_path, start_line=1, end_line=1,
        )],
    )
