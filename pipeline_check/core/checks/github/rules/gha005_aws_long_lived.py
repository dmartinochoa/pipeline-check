"""GHA-005. AWS auth should use OIDC, not long-lived access keys."""
from __future__ import annotations

import re as _re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-005",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Use `aws-actions/configure-aws-credentials` with "
        "`role-to-assume` + `permissions: id-token: write` to obtain "
        "short-lived credentials via OIDC. Remove the static "
        "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "secrets in GitHub Actions can't be rotated on a fine-"
        "grained schedule and remain valid until manually revoked. "
        "OIDC with `role-to-assume` yields short-lived credentials "
        "per workflow run."
    ),
)


_AWS_CONFIGURE_RE = _re.compile(
    r"aws\s+configure\s+set\s+aws_access_key_id\b"
    r"|aws\s+configure\s+set\s+aws_secret_access_key\b"
)

_SECRETS_REF_RE = _re.compile(r"\$\{\{\s*secrets\.")


def _env_has_static_key(env: Any) -> bool:
    """True if an env block sets AWS key vars to non-secrets references."""
    if not isinstance(env, dict):
        return False
    for key, value in env.items():
        key_s = str(key).upper()
        if key_s not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            continue
        if isinstance(value, str) and not _SECRETS_REF_RE.search(value):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    oidc_role = False
    locations: list[Location] = []

    def _flag_static(anchor: Any) -> None:
        """Mark static-key found and record a Location at *anchor*."""
        nonlocal static_keys
        static_keys = True
        if isinstance(anchor, dict):
            line = _line_of(anchor)
            locations.append(Location(path=path, start_line=line, end_line=line))

    for _, job in iter_jobs(doc):
        # Check job-level env for non-secrets AWS key assignments.
        if _env_has_static_key(job.get("env")):
            _flag_static(job.get("env"))
        for step in iter_steps(job):
            uses = step.get("uses") or ""
            if isinstance(uses, str) and uses.startswith(
                "aws-actions/configure-aws-credentials@"
            ):
                w = step.get("with") or {}
                if "role-to-assume" in w:
                    oidc_role = True
                if "aws-access-key-id" in w or "aws-secret-access-key" in w:
                    static_keys = True
                    locations.append(step_location(path, step))
            env = step.get("env") or {}
            if isinstance(env, dict):
                for value in env.values():
                    if isinstance(value, str) and (
                        "AWS_ACCESS_KEY_ID" in value
                        or "AWS_SECRET_ACCESS_KEY" in value
                    ):
                        _flag_static(env)
                        break
            # Detect `aws configure set aws_access_key_id ...` in run blocks.
            run = step.get("run")
            if isinstance(run, str) and _AWS_CONFIGURE_RE.search(run):
                static_keys = True
                locations.append(step_location(path, step))
            # Check step-level env for non-secrets AWS key assignments.
            if _env_has_static_key(step.get("env")):
                _flag_static(step.get("env"))
    doc_env = doc.get("env") or {}
    if isinstance(doc_env, dict):
        for value in doc_env.values():
            if isinstance(value, str) and (
                "AWS_ACCESS_KEY_ID" in value
                or "AWS_SECRET_ACCESS_KEY" in value
            ):
                _flag_static(doc_env)
                break
    if _env_has_static_key(doc_env):
        _flag_static(doc_env)
    if not static_keys and not oidc_role:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow does not configure AWS credentials.",
            recommendation="No action required.", passed=True,
        )
    passed = oidc_role and not static_keys
    if passed:
        desc = "AWS credentials are obtained via OIDC (`role-to-assume`)."
    elif static_keys:
        desc = (
            "Workflow authenticates to AWS with long-lived access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) via static "
            "env vars, `aws configure`, or action inputs. These can't be "
            "rotated on a fine-grained schedule and remain valid until "
            "manually revoked."
        )
    else:
        desc = "AWS credential configuration detected but could not be classified."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations if not passed else [],
    )
