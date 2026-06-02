"""GCB-012, credential-shaped literal in pipeline body.

Scans every string scalar in the document against the cross-provider
credential-pattern catalog (AWS keys, GitHub tokens, Slack tokens,
PEM blocks, JWTs, …). Complements GCB-003 (secrets consumed inline
via ``gcloud secrets versions access``). GCB-003 catches *fetches*,
this catches *pastes*.

Mirrors GHA-008 / GL-008 / BB-008 / ADO-008 / CC-008 / JF-008.
"""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-012",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately. Move the value to "
        "``availableSecrets.secretManager`` and reference it via "
        "``secretEnv:`` so the plaintext never lands in the YAML or "
        "the build logs. For cloud access prefer workload-identity "
        "federation over long-lived keys."
    ),
    docs_note=(
        "Complements GCB-003 (inline ``gcloud secrets versions access``) "
        "and GCB-007 (``/versions/latest`` alias). This rule runs the "
        "shared credential-shape catalog against every string in the "
        "YAML. AWS keys, GitHub PATs, Slack webhooks, JWTs, PEM private "
        "key blocks, and any user-registered ``--secret-pattern`` regex. "
        "Known placeholders like ``EXAMPLE``/``CHANGEME`` are already "
        "filtered upstream so fixtures and docs don't false-match."
    ),
    exploit_example=(
        "# Vulnerable: the AWS access key literal lives in\n"
        "# ``substitutions:``. The Cloud Build YAML is committed\n"
        "# to git and the build log echoes the value whenever the\n"
        "# step prints its environment.\n"
        "substitutions:\n"
        "  _AWS_KEY_ID: AKIAZ3MHALF2TESTHIJK\n"
        "  _AWS_SECRET: aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/AB\n"
        "steps:\n"
        "  - name: amazon/aws-cli@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
        "    env: ['AWS_ACCESS_KEY_ID=${_AWS_KEY_ID}', 'AWS_SECRET_ACCESS_KEY=${_AWS_SECRET}']\n"
        "    args: [s3, cp, ./build, s3://bucket/]\n"
        "\n"
        "# Safe: fetch from Secret Manager via ``availableSecrets``.\n"
        "# The build references the secret by version name; the\n"
        "# value never lands in the build YAML or in plaintext\n"
        "# logs (Cloud Build masks ``secretEnv`` values).\n"
        "steps:\n"
        "  - name: amazon/aws-cli@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
        "    secretEnv: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]\n"
        "    args: [s3, cp, ./build, s3://bucket/]\n"
        "availableSecrets:\n"
        "  secretManager:\n"
        "    - versionName: projects/p/secrets/aws-key-id/versions/1\n"
        "      env: AWS_ACCESS_KEY_ID\n"
        "    - versionName: projects/p/secrets/aws-secret/versions/1\n"
        "      env: AWS_SECRET_ACCESS_KEY"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the pipeline matches a known credential pattern."
        if passed else
        f"Pipeline contains {len(hits)} literal value(s) matching known "
        f"credential patterns (AWS keys, GitHub tokens, Slack tokens, "
        f"JWTs, PEM blocks): {', '.join(hits[:5])}"
        f"{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
