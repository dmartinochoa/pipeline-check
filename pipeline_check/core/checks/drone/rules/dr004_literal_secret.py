"""DR-004. Literal credential in environment / settings."""
from __future__ import annotations

import re

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    from_secret_value,
    iter_steps,
    step_label,
)

RULE = Rule(
    id="DR-004",
    title="Literal credential in step environment / settings",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-321"),
    recommendation=(
        "Move every literal credential into a Drone secret "
        "(``drone secret add --repository OWNER/REPO --name "
        "MY_SECRET --value ...``) and reference it via the "
        "``from_secret:`` mechanism: ``MY_SECRET: { from_secret: "
        "MY_SECRET }``. The same applies to plugin ``settings:`` "
        "blocks. Drone redacts ``from_secret`` values from log "
        "output but does NOT redact literals, so a pasted token "
        "in source ends up in the build log indefinitely."
    ),
    docs_note=(
        "The rule fires on credential-shaped values where the "
        "key name suggests a secret (``token``, ``password``, "
        "``secret``, ``key``, ``apikey``, ``api_key``, "
        "``access_key``, ``private_key``, ``auth``, ``credentials``) "
        "and the value is a plain string rather than a "
        "``{from_secret: NAME}`` reference. AWS-style "
        "``AKIA...`` keys also fire regardless of the key name "
        "(matching the AWS canonical access-key shape). Empty "
        "strings and the explicit literal ``null`` are not "
        "flagged: an empty value is a configuration bug, not a "
        "leaked credential. Same model as BK-002 / TKN-005 / "
        "ARGO-006 in this catalog."
    ),
    known_fp=(
        "Configuration values that happen to use a "
        "credential-shaped key name but never carry a secret "
        "(``DOCKER_CONFIG=/dev/null`` to suppress credential "
        "loading) sometimes trip this rule. Suppress via "
        "ignore-file scoped to the specific step name when this "
        "is the deliberate shape; the broader credential-vocab "
        "match still catches real leaks elsewhere in the "
        "pipeline.",
    ),
    exploit_example=(
        "# Vulnerable: the AWS access key literal is committed to\n"
        "# the pipeline file. Any repo reader sees it; Drone's\n"
        "# build logs print it whenever the step echoes its\n"
        "# environment.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: deploy\n"
        "steps:\n"
        "  - name: upload\n"
        "    image: aws-cli@sha256:abc123...\n"
        "    environment:\n"
        "      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
        "      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "    commands:\n"
        "      - aws s3 cp build/ s3://bucket/\n"
        "\n"
        "# Safe: reference Drone secrets via ``from_secret``. The\n"
        "# actual values live in Drone's secret store (per-repo or\n"
        "# org-level), are masked in logs, and can rotate without\n"
        "# a pipeline-file change.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: deploy\n"
        "steps:\n"
        "  - name: upload\n"
        "    image: aws-cli@sha256:abc123...\n"
        "    environment:\n"
        "      AWS_ACCESS_KEY_ID:\n"
        "        from_secret: aws_access_key_id\n"
        "      AWS_SECRET_ACCESS_KEY:\n"
        "        from_secret: aws_secret_access_key\n"
        "    commands:\n"
        "      - aws s3 cp build/ s3://bucket/"
    ),
)


# Key-name vocabulary that suggests a credential. Anchored at
# segment boundaries (``_``, ``-``, ``.``, start, end) so
# ``API_KEY`` / ``DOCKER-PASSWORD`` / lone ``password`` fire
# but ``OAUTH2_CLIENT_ID`` / ``AUTHOR_NAME`` / ``KEYNOTE`` /
# ``KEY_NUMBER`` don't. Same shape as BK-002's
# ``_SECRET_KEY_RE`` so the cross-provider FP profile stays
# aligned. The vocabulary intentionally omits bare ``auth``,
# the ``oauth`` / ``author`` substring overlap is more
# expensive than the marginal recall gain. CamelCase-only
# names (``apiKey``) aren't matched, Drone keys are
# overwhelmingly underscore-separated or all-lowercase.
_CRED_KEY_RE = re.compile(
    r"(?:^|[_\-.])"
    r"(?:"
    r"TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH_TOKEN"
    r")"
    r"S?(?:$|[_\-.])",
    re.IGNORECASE,
)

# Values that are obvious non-secrets even when the key name
# matches. Booleans / null literals end up in
# ``API_KEY: ${SECRET_FROM_HOOK}`` substitution shapes when the
# YAML loader leaves an interpolated default; filter them so the
# rule doesn't emit a noisy CRITICAL on a config typo. Same
# shape as BK-002's placeholder filter.
_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "true", "false", "none", "null", "0", "1", "n/a", "tbd",
})

# Length floor for credential-shaped values. Matches BK-002:
# real tokens are >= 8 chars; shorter values that happen to land
# in a credential-named field are almost always placeholders or
# config flags rather than leaks.
_MIN_VALUE_LEN = 8

# An interpolated reference (``$SECRET``, ``${SECRET}``) is the
# right shape for Drone too, even though Drone prefers
# ``from_secret:``. Some pipelines source ``${SECRET}`` from the
# host shell or from a CI runner's env; treat it as not-a-leak.
_INTERPOLATION_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")


def _is_credential_key(key: str) -> bool:
    return bool(_CRED_KEY_RE.search(key))


def _value_looks_literal(value: str) -> bool:
    """Heuristics for "this value is a real credential string,
    not a placeholder, env-var reference, or config flag."""
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.lower() in _PLACEHOLDER_VALUES:
        return False
    if _INTERPOLATION_RE.fullmatch(stripped):
        return False
    if len(stripped) < _MIN_VALUE_LEN:
        return False
    return True


_MAX_SCAN_DEPTH = 4


def _scan_block(
    block: object, source_label: str, offenders: list[str], depth: int = 0,
) -> None:
    """Scan one ``environment:`` / ``settings:`` block for literal
    credential values. Recurses into nested config maps / lists (bounded
    depth) so a credential buried in a plugin's nested ``settings:``
    sub-map is still classified. Matches are appended to *offenders*.
    """
    if depth > _MAX_SCAN_DEPTH:
        return
    if isinstance(block, list):
        for i, item in enumerate(block):
            if isinstance(item, (dict, list)):
                _scan_block(item, f"{source_label}[{i}]", offenders, depth + 1)
        return
    if not isinstance(block, dict):
        return
    for key, value in block.items():
        if not isinstance(key, str):
            continue
        # ``from_secret:`` reference, the safe shape, always skip.
        if from_secret_value(value) is not None:
            continue
        if isinstance(value, (dict, list)):
            _scan_block(value, f"{source_label}.{key}", offenders, depth + 1)
            continue
        if not isinstance(value, str):
            continue
        if _is_credential_key(key) and _value_looks_literal(value):
            offenders.append(f"{source_label}.{key}")
            continue
        # A recognized vendor-token shape fires regardless of key name;
        # the length / placeholder filters don't apply because the token
        # shape (AWS / GitHub / GitLab / cloud / AI-provider keys, JWTs,
        # etc., via the shared 49-detector catalog) is itself the leak.
        if find_secret_values([value]):
            offenders.append(f"{source_label}.{key} (token shape)")


def check(pipeline: Pipeline) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        label = step_label(step, idx)
        _scan_block(
            step.get("environment"),
            f"steps.{label}.environment",
            offenders,
        )
        _scan_block(
            step.get("settings"),
            f"steps.{label}.settings",
            offenders,
        )
    # Pipeline-level ``environment:`` is uncommon but legal for
    # global vars; Drone applies it to every step.
    _scan_block(
        pipeline.data.get("environment"),
        "pipeline.environment",
        offenders,
    )
    passed = not offenders
    desc = (
        "No credential-shaped literal in step environment / settings."
        if passed else
        f"{len(offenders)} credential-shaped literal(s) in step "
        f"environment / settings: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. Move to "
        f"``from_secret:``."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
