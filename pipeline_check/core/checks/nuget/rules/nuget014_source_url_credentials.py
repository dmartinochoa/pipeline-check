"""NUGET-014. NuGet.config source URL embeds plaintext credentials."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetConfig

RULE = Rule(
    id="NUGET-014",
    title="NuGet.config source URL embeds plaintext credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-522"),
    recommendation=(
        "Move the credential out of the URL and into the "
        "``<packageSourceCredentials>`` section using the "
        "encrypted-password form. The recommended flow:\n\n"
        "1. Run ``dotnet nuget add source <url> --username <user> "
        "--password <pass> --store-password-in-clear-text=false`` "
        "on the runner. NuGet stores the credential using the "
        "platform's secure-storage API (DPAPI on Windows, "
        "keychain on macOS, libsecret on Linux) and writes an "
        "encrypted form into the user-level NuGet.config.\n"
        "2. For CI, inject the credential at restore time from "
        "the secret manager: ``dotnet nuget add source ... "
        "--password ${env:NUGET_TOKEN}`` is expanded only at "
        "execution time, the literal credential never lives in "
        "the project's NuGet.config.\n"
        "3. If the source must live in the project NuGet.config "
        "for portability, use only the credential-free URL "
        "(``https://nexus.corp/repo``) and rely on the "
        "consumer's user-level config (where credentials are "
        "encrypted) for authentication."
    ),
    docs_note=(
        "Reads each ``NuGet.config`` ``<packageSources>`` entry "
        "and fires when the URL embeds a ``user:pass@`` authority "
        "component. Empty-password forms "
        "(``https://user:@host``) and ``${env:VAR}`` placeholders "
        "are skipped — the former is operator-flagged 'no "
        "credential intended' and the latter resolves at restore "
        "time from the environment.\n\n"
        "Distinct from NUGET-010 (cleartext password in "
        "``<packageSourceCredentials>``) and NUGET-004 (HTTP "
        "scheme): those audit credential and transport posture "
        "in their canonical NuGet locations. This rule catches "
        "the URL-embedded shape, which is the most common "
        "developer mistake when adding a private feed manually."
    ),
    known_fp=(
        "Templated NuGet.config files that materialize a "
        "placeholder credential form (``https://__USER__:"
        "__TOKEN__@host``) and substitute the real value at "
        "build time trip this rule by shape. Suppress per "
        "config when the placeholder marker is stable; the "
        "rule's placeholder skip-list only recognizes "
        "``${env:VAR}`` and ``${VAR}``.",
    ),
    incident_refs=(
        "Pattern across .NET enterprise repositories: a "
        "contributor pastes a Nexus feed URL with embedded "
        "credentials into NuGet.config during a quick test, "
        "intends to replace it before commit, the replacement "
        "never happens. The credential persists in git history "
        "after the fact even if the next commit cleans the file.",
    ),
    exploit_example=(
        "<!-- Vulnerable: credentials pasted into the source URL. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <add key=\"corp-nexus\"\n"
        "         value=\"https://deploy-bot:s3cret@nexus.corp/nuget\" />\n"
        "  </packageSources>\n"
        "</configuration>\n"
        "\n"
        "<!-- Attack: ``git push`` lands the file in repo\n"
        "     history. Every clone (CI cache, contractor\n"
        "     laptop, archived backup) carries the deploy-bot\n"
        "     credential indefinitely. -->\n"
        "\n"
        "<!-- Safe: credential-free URL + user-level encrypted\n"
        "     password. -->\n"
        "<configuration>\n"
        "  <packageSources>\n"
        "    <add key=\"corp-nexus\"\n"
        "         value=\"https://nexus.corp/nuget\" />\n"
        "  </packageSources>\n"
        "</configuration>\n"
        "\n"
        "<!-- ~/.nuget/NuGet/NuGet.Config (per-user, encrypted): -->\n"
        "<packageSourceCredentials>\n"
        "  <corp-nexus>\n"
        "    <add key=\"Username\" value=\"deploy-bot\" />\n"
        "    <add key=\"Password\" value=\"<encrypted-form>\" />\n"
        "  </corp-nexus>\n"
        "</packageSourceCredentials>"
    ),
)


_AUTH_RE = re.compile(
    r"://(?P<user>[^/@:\s\${]+):(?P<pass>[^/@\s\${][^/@\s]*)@",
)


def check(cfg: NuGetConfig) -> Finding:
    offenders: list[str] = []
    for source in cfg.sources:
        if not source.url:
            continue
        m = _AUTH_RE.search(source.url)
        if not m:
            continue
        user = m.group("user")
        host = source.url.split("@", 1)[1].split("/", 1)[0]
        offenders.append(f"{source.name} ({user}@{host})")
    passed = not offenders
    desc = (
        "No NuGet source URLs carry embedded credentials."
        if passed else
        f"{len(offenders)} source URL(s) carry embedded "
        f"credentials: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The credentials "
        f"persist in git history; rotation requires consumer-"
        f"side updates plus history scrub."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=cfg.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
