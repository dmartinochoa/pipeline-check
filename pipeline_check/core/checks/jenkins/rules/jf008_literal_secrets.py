"""JF-008, whole-document credential-shaped literal scan."""
from __future__ import annotations

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
        "credential-pattern catalog. Secrets committed to Groovy "
        "source are visible in every fork and every build log."
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


def check(jf: Jenkinsfile) -> Finding:
    hits = find_secret_values([jf.text])
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
