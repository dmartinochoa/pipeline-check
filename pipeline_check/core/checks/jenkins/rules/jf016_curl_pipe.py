"""JF-016, remote script piped to shell interpreter."""
from __future__ import annotations

from ..._primitives import remote_script_exec
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-016",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository."
    ),
    docs_note=(
        "Detects `curl | bash`, `wget | sh`, and similar patterns "
        "that pipe remote content directly into a shell interpreter "
        "inside a Jenkinsfile. An attacker who controls the remote "
        "endpoint (or poisons DNS / CDN) gains arbitrary code "
        "execution in the build agent."
    ),
    known_fp=(
        "Established vendor installers (get.docker.com, sh.rustup.rs, "
        "bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) "
        "ship via HTTPS from their own CDN and are idiomatic. This "
        "rule defaults to LOW confidence so CI gates can ignore them "
        "with --min-confidence MEDIUM; the finding still surfaces so "
        "teams that want cryptographic verification can audit.",
    ),
    exploit_example=(
        "// Vulnerable: ``curl | bash`` install one-liner trusts\n"
        "// both the network path and the installer host. A\n"
        "// MITM or compromised endpoint runs in the build's\n"
        "// shell with the build's full credential set.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('install') {\n"
        "      steps {\n"
        "        sh 'curl -fsSL https://installer.example.com/cli.sh | bash'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: download, verify a sha256 digest from a\n"
        "// trusted source, then execute.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('install') {\n"
        "      steps {\n"
        "        sh '''\n"
        "          set -e\n"
        "          curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh\n"
        "          echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -\n"
        "          bash /tmp/cli.sh\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    hits = remote_script_exec.scan(jf.text.lower())
    passed = not hits
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this Jenkinsfile."
        if passed else
        f"Remote script piped to interpreter detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
