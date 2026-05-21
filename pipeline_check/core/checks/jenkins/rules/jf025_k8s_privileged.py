"""JF-025. Kubernetes agent pod template runs privileged or mounts hostPath."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import (
    K8S_AGENT_RE,
    K8S_HOSTNS_RE,
    K8S_HOSTPATH_RE,
    K8S_PRIVILEGED_RE,
)

RULE = Rule(
    id="JF-025",
    title="Kubernetes agent pod template runs privileged or mounts hostPath",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250", "CWE-276"),
    recommendation=(
        "Remove ``privileged: true`` from the embedded pod YAML, drop "
        "``hostPath``/``hostNetwork``/``hostPID``/``hostIPC`` entries, "
        "and add a ``securityContext`` with ``runAsNonRoot: true`` and "
        "a ``readOnlyRootFilesystem``. If Docker-in-Docker is genuinely "
        "required, use a rootless daemon (e.g. sysbox) or run the build "
        "on a dedicated privileged pool with stricter branch protection."
    ),
    docs_note=(
        "JF-017 flags inline ``docker run`` commands. This rule targets "
        "the other privileged-mode entry point: Jenkins' Kubernetes "
        "plugin lets pipelines declare ``agent { kubernetes { yaml "
        "'''...''' } }``. A pod running with ``privileged: true`` or "
        "mounting ``hostPath: /`` gives the build container the same "
        "blast radius, container escape, node-credential theft, "
        "cross-tenant contamination on a shared cluster."
    ),
    exploit_example=(
        "// Vulnerable: a Kubernetes agent pod template runs\n"
        "// containers as privileged and mounts hostPath. The\n"
        "// agent pod escapes to the node; the node hosts every\n"
        "// other agent pod on the cluster.\n"
        "pipeline {\n"
        "  agent {\n"
        "    kubernetes {\n"
        "      yaml '''\n"
        "        spec:\n"
        "          containers:\n"
        "            - name: dind\n"
        "              image: docker:24-dind\n"
        "              securityContext:\n"
        "                privileged: true\n"
        "              volumeMounts:\n"
        "                - name: dockersock\n"
        "                  mountPath: /var/run/docker.sock\n"
        "          volumes:\n"
        "            - name: dockersock\n"
        "              hostPath: { path: /var/run/docker.sock }\n"
        "      '''\n"
        "    }\n"
        "  }\n"
        "  stages { stage('build') { steps { sh 'docker build .' } } }\n"
        "}\n"
        "\n"
        "// Safe: rootless builder (Kaniko / BuildKit) in a\n"
        "// non-privileged container. No host path, no host\n"
        "// kernel namespace access.\n"
        "pipeline {\n"
        "  agent {\n"
        "    kubernetes {\n"
        "      yaml '''\n"
        "        spec:\n"
        "          containers:\n"
        "            - name: kaniko\n"
        "              image: gcr.io/kaniko-project/executor@sha256:abc123...\n"
        "              securityContext:\n"
        "                runAsNonRoot: true\n"
        "                runAsUser: 1000\n"
        "                allowPrivilegeEscalation: false\n"
        "                capabilities: { drop: [ALL] }\n"
        "      '''\n"
        "    }\n"
        "  }\n"
        "  stages { stage('build') { steps { sh '/kaniko/executor --context=. --destination=registry/app:tag' } } }\n"
        "}"
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    if not K8S_AGENT_RE.search(jf.text):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not use a Kubernetes agent.",
            recommendation="No action required.", passed=True,
        )
    problems: list[str] = []
    if K8S_PRIVILEGED_RE.search(jf.text):
        problems.append("privileged: true")
    if K8S_HOSTPATH_RE.search(jf.text):
        problems.append("hostPath volume")
    if K8S_HOSTNS_RE.search(jf.text):
        problems.append("hostNetwork/hostPID/hostIPC")
    passed = not problems
    desc = (
        "Kubernetes agent pod template has no privileged-mode markers."
        if passed else
        f"Kubernetes agent pod template exposes host: {', '.join(problems)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
