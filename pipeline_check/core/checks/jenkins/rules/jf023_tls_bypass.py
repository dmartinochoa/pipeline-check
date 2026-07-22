"""JF-023. TLS / certificate verification bypass."""
from __future__ import annotations

from ..._primitives import tls_bypass
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-023",
    title="TLS / certificate verification bypass",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-295",),
    recommendation=(
        "Remove TLS verification bypasses. Fix certificate issues at "
        "the source (install CA certificates, configure proper trust "
        "stores) instead of disabling verification."
    ),
    docs_note=(
        "Detects patterns that disable TLS certificate verification: "
        "`git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, "
        "`npm config set strict-ssl false`, `curl -k`, "
        "`wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and "
        "`GOINSECURE=`. Disabling TLS verification allows MITM injection "
        "of malicious packages, repositories, or build tools."
    ),
    exploit_example=(
        "// Vulnerable: ``git -c http.sslverify=false clone``\n"
        "// (or ``npm config set strict-ssl false``,\n"
        "// ``NODE_TLS_REJECT_UNAUTHORIZED=0``) disables\n"
        "// certificate verification. Any network attacker MITMs\n"
        "// the registry / remote and ships substituted bytes.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('clone') {\n"
        "      steps {\n"
        "        sh 'git -c http.sslverify=false clone https://internal/repo.git'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: install the missing CA into the agent's trust\n"
        "// store and keep verification on.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('clone') {\n"
        "      steps {\n"
        "        sh '''\n"
        "          sudo cp /var/jenkins_home/ca/internal.crt /usr/local/share/ca-certificates/\n"
        "          sudo update-ca-certificates\n"
        "          git clone https://internal/repo.git\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)

def check(jf: Jenkinsfile) -> Finding:
    hits = tls_bypass.scan(jf.text_no_comments)
    passed = not hits
    desc = (
        "No TLS verification bypass patterns detected."
        if passed else
        f"TLS verification bypass detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
