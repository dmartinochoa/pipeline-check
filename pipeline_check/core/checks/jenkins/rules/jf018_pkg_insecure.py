"""JF-018, package install from insecure source."""
from __future__ import annotations

from ...base import PKG_INSECURE_RE, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-018",
    title="Package install from insecure source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Use HTTPS registry URLs. Remove --trusted-host and "
        "--no-verify flags. Pin to a private registry with TLS."
    ),
    docs_note=(
        "Detects package-manager invocations that use plain HTTP "
        "registries (`--index-url http://`, `--registry=http://`) or "
        "disable TLS verification (`--trusted-host`, `--no-verify`) "
        "in a Jenkinsfile. These patterns allow man-in-the-middle "
        "injection of malicious packages."
    ),
    exploit_example=(
        "// Vulnerable: pip uses a plaintext-HTTP index and\n"
        "// ``--trusted-host`` silences hash verification.\n"
        "pipeline {\n"
        "  agent { docker { image 'python@sha256:abc123...' } }\n"
        "  stages {\n"
        "    stage('install') {\n"
        "      steps {\n"
        "        sh '''\n"
        "          pip install --index-url http://internal-pypi.example.com/simple \\\n"
        "            --trusted-host internal-pypi.example.com -r requirements.txt\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: HTTPS + ``--require-hashes``. Internal CA\n"
        "// installed in the agent image's trust store.\n"
        "pipeline {\n"
        "  agent { docker { image 'python@sha256:abc123...' } }\n"
        "  stages {\n"
        "    stage('install') {\n"
        "      steps {\n"
        "        sh '''\n"
        "          pip install --index-url https://internal-pypi.example.com/simple \\\n"
        "            --require-hashes -r requirements.txt\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    matches = PKG_INSECURE_RE.findall(jf.text_no_comments.lower())
    passed = not matches
    desc = (
        "No insecure package install patterns detected in this Jenkinsfile."
        if passed else
        f"Insecure package install detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
