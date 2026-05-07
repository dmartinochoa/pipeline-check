"""BK-002 — Literal secret values inline in ``env:`` blocks."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_label

RULE = Rule(
    id="BK-002",
    title="Literal secret value in pipeline env block",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-532"),
    recommendation=(
        "Move the value out of the pipeline file. Use Buildkite's "
        "agent secrets hooks (``secrets/`` directory or "
        "``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / "
        "``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_"
        "DEFAULT_BRANCH`` env var pulled from a secret manager. The "
        "pipeline.yml is committed to the repo and visible to anyone "
        "with read access."
    ),
    docs_note=(
        "Detection fires on values that look like AWS access keys, "
        "GitHub PATs, OpenAI keys, JWTs, or generic high-entropy "
        "tokens, plus on env-var names that imply a secret "
        "(``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when "
        "the value is a non-empty literal rather than an "
        "interpolation (``$SECRET_FROM_AGENT_HOOK``)."
    ),
)

# Strong patterns — high confidence that the literal is a credential.
_STRONG_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access key
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),                      # AWS STS key
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"),                  # GitHub PAT
    re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"),                  # GitHub OAuth
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI / generic
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\."),  # JWT
)

# Env var names that imply a secret. Matched against the key.
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|API_KEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)s?(?:_|$)",
    re.IGNORECASE,
)

# Values that are clearly not literals: shell expansion or empty.
_INTERPOLATED_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")


def _value_is_literal_secret(key: str, value: str) -> bool:
    """Return True iff (key, value) suggests a hard-coded secret."""
    v = value.strip()
    if not v:
        return False
    if _INTERPOLATED_RE.fullmatch(v):
        return False
    for pat in _STRONG_PATTERNS:
        if pat.search(v):
            return True
    if _SECRET_KEY_RE.search(key):
        # Empty placeholders and obvious non-secrets are out.
        if v.lower() in {"true", "false", "none", "null", "0", "1"}:
            return False
        # Length floor: short values are unlikely to be real secrets.
        if len(v) < 8:
            return False
        return True
    return False


def _scan_env(env: Any) -> list[str]:
    if not isinstance(env, dict):
        return []
    out: list[str] = []
    for k, v in env.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        if _value_is_literal_secret(k, v):
            out.append(k)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    top_env_hits = _scan_env(doc.get("env"))
    if top_env_hits:
        offenders.append(f"top-level env: {', '.join(top_env_hits[:5])}")
    for idx, step in iter_command_steps(doc):
        hits = _scan_env(step.get("env"))
        if hits:
            offenders.append(
                f"{step_label(step, idx)}: {', '.join(hits[:5])}"
            )
    passed = not offenders
    desc = (
        "No literal secret values found in pipeline env blocks."
        if passed else
        f"{len(offenders)} env block(s) contain literal secret values: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Move the values out of "
        f"pipeline.yml and read them from a secret store."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
