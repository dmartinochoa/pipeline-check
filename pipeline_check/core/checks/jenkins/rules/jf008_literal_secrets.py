"""JF-008, whole-document credential-shaped literal scan."""
from __future__ import annotations

import re

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-008",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential. Move the value to a "
        "Jenkins credential and reference it via "
        "`withCredentials([string(credentialsId: '…', variable: '…')])`."
    ),
    docs_note=(
        "Scans the raw Jenkinsfile text against the cross-provider "
        "credential-pattern catalog. Values inside ``environment {}`` "
        "blocks also run through the keyed-hex and entropy passes "
        "(which need YAML-key context to fire). Secrets committed to "
        "Groovy source are visible in every fork and every build log."
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
        "// Vulnerable: a credential-shaped literal in the\n"
        "// Jenkinsfile body. Any repo reader sees it; the\n"
        "// console log echoes it whenever the step prints env.\n"
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
        "    AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "  }\n"
        "  stages {\n"
        "    stage('upload') {\n"
        "      steps {\n"
        "        sh 'aws s3 cp ./build s3://bucket/'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: bind a Jenkins Credentials entry via\n"
        "// withCredentials. The secret resolves at runtime,\n"
        "// is masked in console output, rotates in the\n"
        "// Credentials store.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('upload') {\n"
        "      steps {\n"
        "        withCredentials([usernamePassword(\n"
        "          credentialsId: 'aws-uploader',\n"
        "          usernameVariable: 'AWS_ACCESS_KEY_ID',\n"
        "          passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {\n"
        "          sh 'aws s3 cp ./build s3://bucket/'\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


_ENV_BLOCK_RE = re.compile(
    r"\benvironment\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
    re.DOTALL,
)
_GROOVY_ASSIGN_RE = re.compile(
    r"""(\w+)\s*=\s*(?:'([^']*)'|"([^"]*)"|(\S+))""",
)


def _extract_env_dict(text: str) -> dict[str, str]:
    """Extract key-value pairs from Groovy ``environment { ... }`` blocks.

    Returns a flat dict suitable for ``find_secret_values(doc)`` so
    that the keyed-hex and entropy passes can use YAML-key context
    to detect secrets that the prefix-shape catalog misses.
    """
    result: dict[str, str] = {}
    for block_match in _ENV_BLOCK_RE.finditer(text):
        body = block_match.group(1)
        for assign in _GROOVY_ASSIGN_RE.finditer(body):
            key = assign.group(1)
            value = assign.group(2) or assign.group(3) or assign.group(4) or ""
            if value:
                result[key] = value
    return result


def check(jf: Jenkinsfile) -> Finding:
    hits = find_secret_values([jf.text])
    # The keyed-hex and entropy passes need (key, value) context that
    # a pre-collected string list can't provide. Extract key-value
    # pairs from Groovy environment {} blocks and run a second pass
    # with dict input so those detectors also fire on Jenkins.
    env_dict = _extract_env_dict(jf.text)
    if env_dict:
        extra = find_secret_values(env_dict)
        seen = set(hits)
        for h in extra:
            if h not in seen:
                hits.append(h)
                seen.add(h)
    passed = not hits
    desc = (
        "No string in the Jenkinsfile matches a known credential pattern."
        if passed else
        f"Jenkinsfile contains {len(hits)} literal value(s) matching "
        f"known credential patterns: "
        f"{', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
