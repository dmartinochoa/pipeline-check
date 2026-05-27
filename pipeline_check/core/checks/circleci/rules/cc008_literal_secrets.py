"""CC-008. Config must not contain credential-shaped literals."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-008",
    title="Credential-shaped literal in config body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately. Move the value to "
        "a CircleCI project environment variable or a context and "
        "reference it via the variable name. For cloud access, prefer "
        "OIDC federation over long-lived keys."
    ),
    docs_note=(
        "Every string in the config is scanned against a set of "
        "credential patterns (AWS access keys, GitHub tokens, Slack "
        "tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means "
        "a secret was pasted into YAML, the value is visible in every "
        "fork and every build log and must be treated as compromised."
    ),
    known_fp=(
        "Test fixtures and documentation blobs sometimes embed "
        "credential-shaped strings (JWT samples, vendor example keys). "
        "Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, "
        "Stripe ``sk_test_`` docs keys) are suppressed via the "
        "``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW "
        "confidence.",
    ),
    exploit_example=(
        "# Vulnerable: the AWS access key literal lives in\n"
        "# ``environment:``. The config file is committed to git\n"
        "# and printed in build logs whenever the step echoes its\n"
        "# environment.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/aws@sha256:abc123...\n"
        "    environment:\n"
        "      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
        "      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "    steps:\n"
        "      - run: aws s3 cp build/ s3://bucket/\n"
        "\n"
        "# Safe: reference a project-level / org-level context\n"
        "# variable. The actual credential lives in CircleCI's\n"
        "# encrypted context store, masked in logs, rotatable\n"
        "# without a config-file change.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/aws@sha256:abc123...\n"
        "    steps:\n"
        "      - run: aws s3 cp build/ s3://bucket/\n"
        "workflows:\n"
        "  ship:\n"
        "    jobs:\n"
        "      - deploy:\n"
        "          context: aws-deploy   # AWS_* vars resolve at runtime"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the config matches a known credential pattern."
        if passed else
        f"Config contains {len(hits)} literal value(s) matching known "
        f"credential patterns (AWS keys, GitHub tokens, Slack tokens, "
        f"JWTs): {', '.join(hits[:5])}{'...' if len(hits) > 5 else ''}. "
        f"Secrets committed to YAML are visible in every fork and in "
        f"every build log, and must be considered compromised."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
