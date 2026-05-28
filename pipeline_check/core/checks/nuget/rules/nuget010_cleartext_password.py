"""NUGET-010, NuGet.config stores a feed credential in plaintext."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig

RULE = Rule(
    id="NUGET-010",
    title="NuGet.config stores a feed credential in plaintext",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-256", "CWE-312"),
    recommendation=(
        "Remove the ``<add key=\"ClearTextPassword\" .../>`` element "
        "from ``<packageSourceCredentials>``. If the feed needs auth "
        "for the build, use an environment variable reference "
        "(``%FEED_PASSWORD%`` on the value of an encrypted "
        "``<add key=\"Password\" ...>`` entry, populated at job time) "
        "or NuGet's encrypted-credential workflow "
        "(``nuget sources update -username ... -password ...``, "
        "which writes the DPAPI-encrypted ``Password`` key on "
        "Windows). On Linux / macOS where DPAPI isn't available, "
        "inject the secret at build time via the ``NUGET_CREDENTIALS`` "
        "environment variable or a ``-StoredPasswordInClearText`` "
        "session-scoped source declared in the build script, never "
        "in a checked-in ``NuGet.config``. After removal, rotate the "
        "credential — anyone with read access to the repo history "
        "has it."
    ),
    docs_note=(
        "Fires when a ``NuGet.config`` carries a "
        "``<packageSourceCredentials>`` block whose per-source entry "
        "includes an ``<add key=\"ClearTextPassword\" value=\"...\" />`` "
        "element. The key match is case-insensitive (NuGet itself "
        "treats it that way). The rule does NOT read or echo the "
        "literal credential value — findings only name the source "
        "the credential is bound to so secrets aren't laundered "
        "into reports.\n\n"
        "An encrypted ``<add key=\"Password\" .../>`` entry is the "
        "DPAPI-encrypted form NuGet writes when you run "
        "``nuget sources update -username ... -password ...`` on "
        "Windows. That key is NOT flagged here — its value is "
        "unreadable without the original user's key material. The "
        "rule's surface is specifically the ``ClearTextPassword`` "
        "key, which stores the literal credential in committable "
        "plaintext.\n\n"
        "Note: a session-scoped ``NuGet.config`` written by the "
        "build script (never committed) can legitimately use "
        "``ClearTextPassword`` to pass a token from an environment "
        "variable to ``dotnet restore``. If you scan a tree that "
        "contains such a file, suppress on the specific path and "
        "rule pair with a rationale; the rule has no way to tell a "
        "build-script-generated config apart from a hand-committed "
        "one."
    ),
    known_fp=(
        "Build-script-generated ``NuGet.config`` files written into "
        "a workspace at job time legitimately use "
        "``ClearTextPassword`` because the file isn't committed. The "
        "rule can't distinguish those from a checked-in config; "
        "suppress with a rationale on the specific path.",
    ),
    incident_refs=(
        "NuGet credentials in repo history have driven multiple "
        "incidents where a private feed token leaked via a "
        "``NuGet.config`` committed to a public mirror or to an "
        "open-source release branch; once in git history, the "
        "credential is recoverable forever (even after deletion).",
    ),
    exploit_example=(
        "<!-- Vulnerable: ``ClearTextPassword`` puts the literal\n"
        "     credential into committable XML. Once this lands in\n"
        "     ``git log -p``, the token is leaked permanently;\n"
        "     removing the line in a later commit does NOT recover\n"
        "     the secret. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        '    <add key="internal" value="https://nuget.corp.local/v3/index.json" />\n'
        "  </packageSources>\n"
        "  <packageSourceCredentials>\n"
        "    <internal>\n"
        '      <add key="Username" value="ci-bot" />\n'
        '      <add key="ClearTextPassword" value="pat_3vDX..." />\n'
        "    </internal>\n"
        "  </packageSourceCredentials>\n"
        "</configuration>\n"
        "\n"
        "<!-- Safe: pass the credential as an environment variable\n"
        "     at build time; NuGet expands ``%VAR%`` in the password\n"
        "     attribute. The committed XML carries no secret. -->\n"
        "<packageSourceCredentials>\n"
        "  <internal>\n"
        '    <add key="Username" value="ci-bot" />\n'
        '    <add key="ClearTextPassword" value="%NUGET_FEED_TOKEN%" />\n'
        "  </internal>\n"
        "</packageSourceCredentials>"
    ),
)


def check(config: NuGetConfig) -> Finding:
    offenders = [c.source for c in config.credentials if c.has_cleartext_password]
    passed = not offenders
    if passed:
        desc = (
            "NuGet.config carries no <packageSourceCredentials> "
            "entry with a ClearTextPassword key."
        )
    else:
        unique = sorted(set(offenders))
        joined = ", ".join(unique[:5])
        more = "…" if len(unique) > 5 else ""
        desc = (
            f"{len(unique)} <packageSourceCredentials> entry / "
            f"entries store a feed credential in plaintext: {joined}{more}. "
            f"Anyone with read access to the repo (now or in future "
            f"history) recovers the token. Rotate the credential, "
            f"then switch to an encrypted Password key or an env-var "
            f"placeholder."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=config.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
