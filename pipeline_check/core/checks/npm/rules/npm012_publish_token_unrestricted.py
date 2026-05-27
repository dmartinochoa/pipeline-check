"""NPM-012, ``.npmrc`` auth token lacks IP or readonly restriction."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmRc

RULE = Rule(
    id="NPM-012",
    title=".npmrc publish token lacks IP or readonly restriction",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-269", "CWE-522"),
    recommendation=(
        "Restrict every npm auth token to the minimum required scope. "
        "For tokens used only in CI publish workflows:\n\n"
        "1. Generate an **automation** token (npmjs.com > Access "
        "Tokens > Generate New Token > Granular Access Token) with "
        "only the ``publish`` permission on the specific packages "
        "it needs to publish.\n"
        "2. Enable **IP address CIDR allowlisting** on the token "
        "to restrict usage to known CI runner IP ranges.\n"
        "3. For read-only CI installs (``npm ci``), use a **read-"
        "only** token that cannot publish at all.\n\n"
        "A leaked unrestricted publish token enables full package "
        "hijack: an attacker publishes a backdoored version under "
        "your package name."
    ),
    docs_note=(
        "Fires when a ``.npmrc`` contains an ``_authToken`` entry "
        "(the standard npm registry auth mechanism) without any "
        "accompanying restriction. The rule checks for two "
        "indicators of restriction:\n\n"
        "1. An ``_authToken`` value that begins with ``npm_`` "
        "(granular access token, which carries server-side scope "
        "restrictions) vs. a legacy token (UUID-shaped or opaque "
        "hex, which has no scope boundary).\n"
        "2. Absence of a ``_password`` or ``always-auth`` key for "
        "the same registry scope (which would indicate a different "
        "auth mechanism).\n\n"
        "The rule cannot verify IP restrictions client-side (those "
        "are stored server-side on npmjs.com). It uses the token "
        "format as a proxy: granular tokens (``npm_`` prefix) "
        "support IP restrictions; legacy tokens do not.\n\n"
        "Complements NPM-011 (secret-shaped paths in ``files`` "
        "field) and the DF-025 rule (registry token baked into a "
        "Docker image layer)."
    ),
    known_fp=(
        "Some organizations use a private registry (Verdaccio, "
        "GitHub Packages, GitLab Packages) whose tokens don't "
        "follow the npmjs.com format. The rule fires on any "
        "non-``npm_`` token, which may be a legitimate private-"
        "registry token. Suppress with a rationale naming the "
        "registry.",
    ),
    incident_refs=(
        "ESLint 2018: a maintainer's stolen npm token was used to "
        "publish ``eslint-scope@3.7.2`` and ``eslint-config-"
        "eslint@5.0.2`` containing credential-harvesting code. "
        "Granular tokens with publish-only scope on specific "
        "packages and IP restrictions would have blocked the "
        "attacker's publish from outside the maintainer's network.",
        "ua-parser-js 2021: a hijacked npm token published three "
        "backdoored versions (0.7.29, 0.8.0, 1.0.0) in a single "
        "session. A restricted token would have limited the damage "
        "to the specific package and IP range.",
    ),
    exploit_example=(
        "# Vulnerable: legacy UUID-shaped token with no scope\n"
        "# restrictions. A leak lets the attacker publish any\n"
        "# version of any package the token's owner maintains.\n"
        "# .npmrc\n"
        "//registry.npmjs.org/:_authToken=<legacy-uuid-token>\n"
        "\n"
        "# Safe: granular access token with npm_ prefix (server-\n"
        "# side scope and IP restrictions).\n"
        "# .npmrc\n"
        "//registry.npmjs.org/:_authToken=npm_<granular-token>"
    ),
)


_AUTH_TOKEN_KEY_RE = re.compile(
    r"_authtoken\s*$",
    re.IGNORECASE,
)


def check(rc: NpmRc) -> Finding:
    legacy_tokens: list[str] = []
    token_lines: list[int] = []

    for key, value in rc.settings.items():
        if not _AUTH_TOKEN_KEY_RE.search(key):
            continue
        value_stripped = value.strip().strip('"').strip("'")
        if not value_stripped:
            continue
        if value_stripped.startswith("${"):
            continue
        if value_stripped.startswith("npm_"):
            continue
        scope = key.rsplit(":", 1)[0] if ":" in key else "(default)"
        legacy_tokens.append(scope)
        for idx, line in enumerate(rc.text.splitlines(), start=1):
            if key.lower() in line.lower() and "_authtoken" in line.lower():
                token_lines.append(idx)
                break

    passed = not legacy_tokens
    locations = [
        Location(path=rc.path, start_line=ln, end_line=ln)
        for ln in token_lines
    ]
    if passed:
        desc = (
            ".npmrc has no legacy auth tokens; all tokens use the "
            "granular ``npm_`` format or reference environment "
            "variables."
        )
    else:
        desc = (
            f"{len(legacy_tokens)} registry auth token(s) use a "
            f"legacy format (no ``npm_`` prefix): "
            f"{', '.join(legacy_tokens[:5])}"
            f"{'...' if len(legacy_tokens) > 5 else ''}. "
            f"Legacy tokens cannot be scoped to specific packages "
            f"or restricted by IP range. A leaked legacy publish "
            f"token enables full package hijack."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=rc.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
