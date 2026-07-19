"""GL-003, `variables:` blocks must not hold literal credential values."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import SECRETISH_KEY_RE, aws_key_in, is_placeholder_value

RULE = Rule(
    id="GL-003",
    title="Variables contain literal secret values",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Store credentials as protected + masked CI/CD variables in "
        "project or group settings, and reference them by name from "
        "the YAML. For cloud access prefer short-lived OIDC tokens."
    ),
    docs_note=(
        "Scans `variables:` at the top level and on each job for "
        "entries whose KEY looks credential-shaped and whose VALUE "
        "is a literal string (not a `$VAR` reference). AWS access "
        "keys are detected by value pattern regardless of key name."
    ),
    exploit_example=(
        "# Vulnerable: literal AWS access key in pipeline-level\n"
        "# ``variables:``. The ``.gitlab-ci.yml`` is committed\n"
        "# to git, printed in build logs whenever a job echoes\n"
        "# its environment, visible to any repo reader.\n"
        "variables:\n"
        "  AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK\n"
        "  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "deploy:\n"
        "  script: [aws s3 cp ./build s3://bucket/]\n"
        "\n"
        "# Safe: store credentials as protected + masked CI/CD\n"
        "# variables in GitLab Settings. The pipeline file\n"
        "# references the env names; values resolve at runtime\n"
        "# and are masked in logs.\n"
        "deploy:\n"
        "  script: [aws s3 cp ./build s3://bucket/]\n"
        "  # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY come from\n"
        "  # project-level protected + masked CI/CD variables"
    ),
)


#: GitLab analyzer/template config-variable key prefixes. Their values
#: are scanner configuration (paths, flags), not credentials.
_CONFIG_KEY_PREFIXES = (
    "SECRET_DETECTION_", "SAST_", "DAST_", "DEPENDENCY_SCANNING_",
    "CONTAINER_SCANNING_", "CS_", "DS_", "COVERAGE_",
)
#: Suffixes that make a credential-named key a pointer (a path / name /
#: URL) rather than the secret itself.
_REFERENCE_KEY_SUFFIXES = (
    "_PATH", "_FILE", "_DIR", "_NAME", "_URL", "_URI", "_ENABLED", "_ID",
)
_BENIGN_VALUES = frozenset({
    "true", "false", "yes", "no", "on", "off", "none", "null",
})


def _is_config_var(key: str, raw: str) -> bool:
    """Whether ``key: raw`` is scanner/template config, not a secret."""
    up = key.upper()
    if up.startswith(_CONFIG_KEY_PREFIXES):
        return True
    if up.endswith(_REFERENCE_KEY_SUFFIXES):
        return True
    v = raw.strip()
    if v.lower() in _BENIGN_VALUES:
        return True
    if v.startswith(("/", "./", "../", "~/")):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    def _scan(varmap: Any, where: str) -> None:
        if not isinstance(varmap, dict):
            return
        for key, value in varmap.items():
            if not isinstance(key, str):
                continue
            raw = value.get("value") if isinstance(value, dict) else value
            if not isinstance(raw, str):
                continue
            if aws_key_in(raw):
                offenders.append(f"{where}.{key} (AWS access key)")
                continue
            if (
                SECRETISH_KEY_RE.search(key)
                and raw and "$" not in raw
                and not is_placeholder_value(raw)
                and not _is_config_var(key, raw)
            ):
                offenders.append(f"{where}.{key}")

    _scan(doc.get("variables"), "<top>")
    for name, job in iter_jobs(doc):
        _scan(job.get("variables"), name)

    passed = not offenders
    desc = (
        "No `variables:` entry holds a literal credential-shaped value."
        if passed else
        f"{len(offenders)} variable(s) contain literal credential values: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}. "
        f"Secrets committed to CI YAML are visible in every fork and "
        f"every pipeline run log."
    )
    severity = Severity.CRITICAL if any("AWS" in o for o in offenders) else Severity.HIGH
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
