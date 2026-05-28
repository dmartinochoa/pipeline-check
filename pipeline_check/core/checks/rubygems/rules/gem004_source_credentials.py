"""GEM-004. Source URL embeds plaintext credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-004",
    title="Gemfile source URL embeds plaintext credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Move the credential out of the Gemfile and into "
        "``bundle config set --global``: ``bundle config set "
        "https://gems.corp/ user:token``. Bundler stores those "
        "credentials in ``~/.bundle/config`` (per-user, "
        "git-ignored by Bundler convention), and "
        "``$BUNDLE_<HOSTNAME>`` reads from the environment so "
        "the CI runner can mount the secret out-of-band. The "
        "URL in the Gemfile should be just the host and path "
        "with no userinfo. After scrubbing the manifest, rotate "
        "the credential — anything that was committed to git is "
        "compromised."
    ),
    docs_note=(
        "Fires when a ``source`` URL parses to a userinfo "
        "segment (``https://user:pass@host/...``) and the "
        "password segment is not a Bundler / shell-expansion "
        "placeholder (``$ENV_VAR`` / ``#{ENV[...]}``). Common "
        "case: copy-pasted setup script from internal docs that "
        "embedded the token literally."
    ),
    known_fp=(
        "URLs that embed only a username (``https://deploy@host/``) "
        "for OAuth-style flows without a literal secret. The "
        "rule allows usernames; only user:password pairs trip it.",
    ),
    incident_refs=(
        "Standing-up a private gem mirror and copy-pasting the "
        "bootstrap URL straight into the Gemfile is a "
        "well-trodden footgun; the credential lands in git "
        "history and is exposed to anyone who can read the repo.",
    ),
    exploit_example=(
        "# Vulnerable: token in the manifest URL.\n"
        "source \"https://bot:s3cr3t@gems.corp/private\"\n"
        "gem \"internal-gem\", \"1.0.0\"\n"
        "\n"
        "# Safe: scrub manifest, move to bundle config.\n"
        "# Gemfile:\n"
        "source \"https://gems.corp/private\"\n"
        "gem \"internal-gem\", \"1.0.0\"\n"
        "# CI runner setup (out of git):\n"
        "$ bundle config set --local gems.corp bot:s3cr3t\n"
        "# Or via env: BUNDLE_GEMS__CORP=bot:s3cr3t bundle install"
    ),
)


_CREDS_RE = re.compile(
    r"^[a-z][a-z0-9+\-.]*://[^:/@?\s]+:([^@/\s]+)@",
    re.IGNORECASE,
)


def _is_placeholder(secret: str) -> bool:
    s = secret.strip()
    if not s:
        return True
    return any(m in s for m in (
        "$", "#{", "{{", "%{", "<",
    ))


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for src in pom.sources:
        m = _CREDS_RE.match(src.url)
        if not m:
            continue
        if _is_placeholder(m.group(1)):
            continue
        # Redact the secret in the rendered output.
        redacted = _CREDS_RE.sub(
            lambda mm: (
                mm.group(0)[: mm.start(1) - mm.start(0)] + "***@"
            ),
            src.url,
        )
        offenders.append(redacted)
        locations.append(Location(
            path=pom.path,
            start_line=src.line_no, end_line=src.line_no,
        ))
    passed = not offenders
    if passed:
        desc = "No Gemfile source embeds plaintext credentials."
    else:
        rendered = ", ".join(offenders[:3])
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} source URL / URLs embed plaintext "
            f"credentials: {rendered}{suffix}. Move the secret to "
            f"``bundle config`` or $BUNDLE_<HOST> and rotate it."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
