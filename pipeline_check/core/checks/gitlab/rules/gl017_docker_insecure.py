"""GL-017, docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import DOCKER_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="GL-017",
    title="Docker run with insecure flags (privileged/host mount)",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250",),
    recommendation=(
        "Remove --privileged and --cap-add flags. Use minimal volume "
        "mounts. Prefer rootless containers."
    ),
    docs_note=(
        "Flags like `--privileged`, `--cap-add`, `--net=host`, or "
        "host-root volume mounts (`-v /:/`) in a pipeline give the "
        "container full access to the CI runner, enabling container "
        "escape and lateral movement."
    ),
    exploit_example=(
        "# Vulnerable: ``docker run --privileged`` plus the host\n"
        "# Docker socket inside a GitLab Runner job gives the\n"
        "# container full kernel access. A compromise escapes\n"
        "# to the runner host and from there to every other job\n"
        "# sharing it.\n"
        "integration:\n"
        "  image: docker:24\n"
        "  services: [docker:24-dind]\n"
        "  script:\n"
        "    - docker run --privileged \\\n"
        "        -v /var/run/docker.sock:/var/run/docker.sock \\\n"
        "        myapp:test ./integration.sh\n"
        "\n"
        "# Safe: drop ``--privileged`` and the socket mount. If\n"
        "# the job needs to build images, use Kaniko / BuildKit\n"
        "# rootless. Run integration tests in a normal container.\n"
        "integration:\n"
        "  image: myapp@sha256:abc123...\n"
        "  script:\n"
        "    - ./integration.sh"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=DOCKER_INSECURE_RE.findall,
    pass_desc="No insecure docker run flags detected in this pipeline.",
    fail_desc=lambda matches: (
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    ),
)
