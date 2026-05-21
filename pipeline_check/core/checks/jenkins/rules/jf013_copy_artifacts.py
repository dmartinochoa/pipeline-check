"""JF-013, copyArtifacts must be paired with a verification step."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import COPY_ARTIFACTS_RE, VERIFY_RE

RULE = Rule(
    id="JF-013",
    title="copyArtifacts ingests another job's output unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step before consuming the artifact: "
        "`sh 'sha256sum -c manifest.sha256'` against a manifest the "
        "producer signed, or `cosign verify` over the artifact "
        "directly. Restrict the upstream job to non-PR builds via "
        "branch protection if verification isn't feasible."
    ),
    docs_note=(
        "Recognizes both `copyArtifacts(projectName: ...)` and the "
        "older `step([$class: 'CopyArtifact', ...])` form. If the "
        "upstream job accepts multibranch or PR builds, the "
        "artifact may have been produced by attacker-controlled code."
    ),
    exploit_example=(
        "// Vulnerable: ``app-build`` is a multibranch job that runs\n"
        "// on every PR branch. A contributor opens a PR, the PR\n"
        "// build produces a malicious ``release.jar`` as its\n"
        "// artifact, and ``deploy`` copies and runs that jar inside\n"
        "// the controller's credential context. The deploy job\n"
        "// has no way to know the upstream artifact came from an\n"
        "// untrusted ref.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('deploy') {\n"
        "      steps {\n"
        "        copyArtifacts(\n"
        "          projectName: 'app-build',\n"
        "          filter: 'release.jar',\n"
        "          selector: lastSuccessful()\n"
        "        )\n"
        "        sh 'java -jar release.jar'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: verify a producer-signed manifest before executing\n"
        "// anything from the copied directory. The verify step must\n"
        "// come BEFORE any step that reads the artifact.\n"
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('deploy') {\n"
        "      steps {\n"
        "        copyArtifacts(\n"
        "          projectName: 'app-build',\n"
        "          filter: 'release.jar,release.jar.sig,manifest.sha256',\n"
        "          selector: lastSuccessful()\n"
        "        )\n"
        "        sh 'sha256sum -c manifest.sha256'\n"
        "        sh 'cosign verify-blob --signature release.jar.sig release.jar'\n"
        "        sh 'java -jar release.jar'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    ingests = bool(COPY_ARTIFACTS_RE.search(jf.text))
    if not ingests:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not use copyArtifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = bool(VERIFY_RE.search(jf.text))
    desc = (
        "copyArtifacts is paired with a verification step."
        if passed else
        "Pipeline pulls artifacts from another Jenkins job via "
        "`copyArtifacts` but no signature/checksum verification "
        "step is present."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
