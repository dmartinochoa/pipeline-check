"""BB-008, whole-document credential-shaped literal scan."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="BB-008",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential. Move the value to a Secured "
        "Repository or Deployment Variable and reference it by name."
    ),
    docs_note=(
        "Complements BB-003 (variable-name scan). BB-008 checks "
        "every string in the pipeline against the cross-provider "
        "credential-pattern catalog, catches secrets pasted into "
        "script bodies or environment blocks."
    ),
    known_fp=(
        "Test fixtures and documentation blobs sometimes embed "
        "credential-shaped strings (JWT samples, AKIAI... examples). "
        "The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is "
        "deliberately NOT suppressed, if it appears in a real "
        "pipeline it almost always means a copy-paste from docs was "
        "never substituted. Defaults to LOW confidence.",
    ),
    exploit_example=(
        "# Vulnerable: a credential-shaped literal anywhere in\n"
        "# the pipeline body (step env, inline script, after-\n"
        "# script body). Anyone with repo read sees it; build\n"
        "# logs echo it whenever the step prints its env.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - curl -H \"Authorization: Bearer ghp_abcdef1234567890abcdef1234567890abcdef12\" \\\n"
        "              https://api.github.com/repos/org/repo/issues\n"
        "\n"
        "# Safe: route the credential through a secured\n"
        "# Repository / Workspace Variable. The pipeline body\n"
        "# carries the env name, never the value.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          # GITHUB_TOKEN is a secured Workspace Variable\n"
        "          - curl -H \"Authorization: Bearer $GITHUB_TOKEN\" \\\n"
        "              https://api.github.com/repos/org/repo/issues"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the pipeline matches a known credential pattern."
        if passed else
        f"Pipeline contains {len(hits)} literal value(s) matching "
        f"known credential patterns (AWS keys, GitHub tokens, Slack "
        f"tokens, JWTs): {', '.join(hits[:5])}"
        f"{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
