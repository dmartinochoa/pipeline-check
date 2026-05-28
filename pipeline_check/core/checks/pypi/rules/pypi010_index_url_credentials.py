"""PYPI-010. Requirements / config carries an index URL with embedded credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import RequirementsFile, get_option_values

RULE = Rule(
    id="PYPI-010",
    title="Requirements file carries an index URL with embedded credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Move the credential out of the URL and into the environment "
        "or a dedicated config file the host respects:\n\n"
        "* Set ``PIP_INDEX_URL=https://my.org/simple`` and pass the "
        "credentials via ``PIP_KEYRING_PROVIDER=subprocess`` plus "
        "``~/.config/pip/pip.conf`` (which lives outside the repo).\n"
        "* For poetry, use ``poetry config http-basic.<repo-name> "
        "<user> <pass>`` so credentials land in the user's keyring "
        "rather than the manifest.\n"
        "* For CI runners, inject the credentials at install time "
        "via ``PIP_INDEX_URL=https://${TOKEN}@my.org/simple`` "
        "from a CI secret variable and never commit the resolved "
        "form.\n\n"
        "Credentials embedded in a committed ``--index-url`` flag "
        "lock the password into git history. The value persists in "
        "every clone, every CI cache, and every backup; rotation "
        "requires consumer-side updates *plus* history scrub before "
        "the leaked credential stops being useful to an attacker."
    ),
    docs_note=(
        "Reads top-level ``--index-url`` / ``--extra-index-url`` / "
        "``-i`` options from each requirements file and fires when "
        "the URL's authority component carries an ``<user>:<pass>@`` "
        "prefix. Empty-password forms (``https://user:@host``) and "
        "``${VAR}`` placeholders are skipped — the former is "
        "operator-flagged as 'no credential intended' and the "
        "latter resolves at install time from the environment "
        "rather than the manifest text.\n\n"
        "Mirrors NPM-013-style risks for npm's ``.npmrc`` ``_authToken`` "
        "but adapted to pip's URL-embedded form. The npm rule has a "
        "dedicated registry-token slot; pip and poetry leak the "
        "credential at the URL level instead."
    ),
    known_fp=(
        "Internal templating tools that emit a placeholder credential "
        "form (``https://__TOKEN__:@my.org``) and substitute the "
        "real value at install time trip this rule by shape. "
        "Suppress per file when the template marker is stable; the "
        "rule's placeholder skip-list only recognizes ``${...}``.",
    ),
    incident_refs=(
        "Long-running pattern of internal artifact-registry "
        "credentials leaking through requirements files committed "
        "to public mirrors. The credential's audit trail (last "
        "rotated, who has it) is lost the moment the file lands in "
        "a clone an attacker controls; the cost is rotation plus "
        "follow-up reviews of every system that used the leaked "
        "credential during the exposure window.",
    ),
    exploit_example=(
        "# Vulnerable: credential pasted into --extra-index-url.\n"
        "# requirements.txt\n"
        "--extra-index-url https://deploy-bot:s3cret-rotate-me@nexus.corp.example/simple/\n"
        "internal-utils==1.2.3\n"
        "\n"
        "# Attack: ``git push`` lands the file in repo history.\n"
        "# Any clone (CI cache, contractor laptop, archived\n"
        "# backup) carries the credential indefinitely. A leak\n"
        "# of the repo turns into full read-access to the\n"
        "# internal Nexus, including any private packages that\n"
        "# weren't otherwise meant to be visible.\n"
        "\n"
        "# Safe: keep the URL credential-free in the manifest and\n"
        "# inject the secret at install time from the environment.\n"
        "# requirements.txt\n"
        "--extra-index-url https://nexus.corp.example/simple/\n"
        "internal-utils==1.2.3\n"
        "\n"
        "# CI:\n"
        "#   export PIP_INDEX_URL=\"https://${TOKEN}@nexus.corp.example/simple/\"\n"
        "#   pip install -r requirements.txt"
    ),
)


# Match ``://user:pass@host``. Excludes empty-password forms and
# ``${var}`` placeholders so the rule's signal stays clean.
_AUTH_RE = re.compile(
    r"://(?P<user>[^/@:\s\${]+):(?P<pass>[^/@\s\${][^/@\s]*)@",
)


def check(rf: RequirementsFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for flag in ("--index-url", "--extra-index-url", "-i"):
        for value in get_option_values(rf, flag):
            m = _AUTH_RE.search(value)
            if not m:
                continue
            host = value.split("@", 1)[1].split("/", 1)[0]
            user = m.group("user")
            offenders.append(f"{flag} {user}@{host}")
            # Best-effort line: the literal flag in the file body.
            line_no = 1
            if flag in rf.text:
                line_no = (
                    rf.text[:rf.text.index(flag)].count("\n") + 1
                )
            locations.append(Location(
                path=rf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No index-URL options carry embedded credentials."
        if passed else
        f"{len(offenders)} index-URL option(s) carry embedded "
        f"credentials: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The credentials "
        f"land in git history; rotation requires consumer-side "
        f"updates plus history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
