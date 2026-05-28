"""GEM-009. .bundle/config committed with embedded credentials."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-009",
    title=".bundle/config committed with embedded credentials",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-538"),
    recommendation=(
        "Remove ``.bundle/config`` (and the whole ``.bundle/`` "
        "directory) from version control and add ``.bundle/`` "
        "to ``.gitignore``. Bundler's documented convention is "
        "to leave that directory out of git — it's a per-user, "
        "per-runner config carrying credentials and "
        "environment-specific settings. On CI, export the "
        "credential through the matching ``$BUNDLE_<HOST>__*`` "
        "environment variable instead so the runner mounts the "
        "secret out-of-band and no committed file ever holds "
        "it.\n\n"
        "After removing the file from the working tree, rotate "
        "every credential the file ever contained. ``git "
        "filter-repo`` can remove the file from history, but "
        "rotation is the irrevocable step — anyone who cloned "
        "the repo while the file was tracked has the credential."
    ),
    docs_note=(
        "Fires when the Gemfile's directory has a "
        "``.bundle/config`` sibling and the YAML body contains "
        "at least one ``BUNDLE_<HOST>__USERNAME`` / "
        "``BUNDLE_<HOST>__PASSWORD`` / ``BUNDLE_<HOST>__TOKEN`` "
        "entry whose value is a literal (non-placeholder). "
        "Placeholder values (``<%= ENV[...] %>`` / ``$ENV`` / "
        "``${VAR}``) are ignored. Bundler accepts both "
        "double-underscore (Bundler 2.x) and single-colon "
        "(legacy) variants of the key."
    ),
    known_fp=(
        "Read-only public-mirror credentials may legitimately "
        "live in ``.bundle/config`` for offline build runners. "
        "Even then, the file shouldn't be in git history — "
        "mount it on the runner via the ``$BUNDLE_*`` env "
        "vars. Suppress per-repo with a one-line rationale.",
    ),
    incident_refs=(
        "Recurring pattern: a developer runs ``bundle config "
        "set --local gems.corp user:token`` to fix a local "
        "build, then commits the resulting ``.bundle/config`` "
        "to track ``BUNDLE_DEPLOYMENT`` / ``BUNDLE_FROZEN`` "
        "settings — without realizing the credential is in the "
        "same file. ``--global`` writes to ``~/.bundle/config`` "
        "(out of git scope) but ``--local`` writes to "
        "``./.bundle/config`` (in git scope unless ignored).",
    ),
    exploit_example=(
        "# Vulnerable: .bundle/config committed next to Gemfile.\n"
        "$ ls\n"
        "Gemfile  Gemfile.lock  .bundle/\n"
        "$ cat .bundle/config\n"
        "---\n"
        "BUNDLE_GEMS__CORP: bot:s3cr3t\n"
        "BUNDLE_DEPLOYMENT: \"true\"\n"
        "\n"
        "# Safe: gitignore the directory, mount on the runner.\n"
        "# .gitignore:\n"
        "/.bundle/\n"
        "# CI step:\n"
        "export BUNDLE_GEMS__CORP=\"bot:$RUBYGEMS_TOKEN\"\n"
        "bundle config set --local deployment true"
    ),
)


# ``BUNDLE_<HOSTNAME>``-shaped key. The hostname segment uses
# double-underscore in 2.x (``gems.corp`` -> ``GEMS__CORP``); we
# stop at the first ``: `` so the value can be captured by a sibling
# regex.
_CREDENTIAL_KEY_RE = re.compile(
    r"^\s*(BUNDLE_[A-Z0-9_]+)\s*[:=]\s*(?P<val>.+)$",
)

# Substrings within a BUNDLE_<HOST>_ key name that flag the entry as
# carrying a credential rather than a plain config flag (``DEPLOYMENT``
# / ``FROZEN`` etc.).
_CREDENTIAL_MARKERS: tuple[str, ...] = (
    "USERNAME", "PASSWORD", "TOKEN", "API_KEY",
    "_USER", "_PASS",
    # ``BUNDLE_GITHUB__COM`` and similar host keys take their value
    # *as* the credential (``user:token``). Bundler treats them as
    # credential carriers in either form.
    "BUNDLE_GITHUB__", "BUNDLE_GEMS__", "BUNDLE_RUBYGEMS__",
    "BUNDLE_GITLAB__", "BUNDLE_BITBUCKET__",
)


def _looks_like_credential_key(key: str) -> bool:
    return any(m in key for m in _CREDENTIAL_MARKERS)


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    if not v:
        return True
    return any(m in v for m in (
        "<%=", "ENV[", "ENV.fetch", "$", "{{", "<", "%env(",
    ))


def check(pom: GemFile) -> Finding:
    if not pom.bundle_config_path:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "No .bundle/config found next to Gemfile."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    for raw_line in pom.bundle_config_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _CREDENTIAL_KEY_RE.match(raw_line)
        if not m:
            continue
        key = m.group(1)
        if not _looks_like_credential_key(key):
            continue
        value = m.group("val")
        if _is_placeholder(value):
            continue
        offenders.append(key)

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.bundle_config_path,
            description=(
                f".bundle/config present at "
                f"``{pom.bundle_config_path}`` but carries no "
                "literal credential values."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    rendered = ", ".join(offenders[:5])
    suffix = "…" if len(offenders) > 5 else ""
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.bundle_config_path,
        description=(
            f".bundle/config committed at "
            f"``{pom.bundle_config_path}`` carries literal "
            f"credentials in {rendered}{suffix}. Add "
            f"``/.bundle/`` to .gitignore, mount via "
            f"$BUNDLE_<HOST>__* env vars on the runner, and "
            f"rotate every secret the file ever held."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=[Location(
            path=pom.bundle_config_path, start_line=1, end_line=1,
        )],
    )
