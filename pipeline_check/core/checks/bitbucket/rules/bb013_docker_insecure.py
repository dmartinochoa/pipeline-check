"""BB-013, docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import DOCKER_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="BB-013",
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
        "container full access to the build runner, enabling container "
        "escape and lateral movement."
    ),
    exploit_example=(
        "# Vulnerable: ``docker run --privileged`` plus the host\n"
        "# Docker socket inside a Bitbucket step. The step is\n"
        "# already a container; granting it privileged access\n"
        "# and the runner's docker.sock collapses every isolation\n"
        "# boundary the pipeline had.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        services: [docker]\n"
        "        script:\n"
        "          - docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock \\\n"
        "              myapp:test ./integration.sh\n"
        "\n"
        "# Safe: drop ``--privileged`` and the socket mount. If\n"
        "# the build needs to build an image, use Kaniko /\n"
        "# BuildKit rootless instead.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        services: [docker]\n"
        "        script:\n"
        "          - docker run myapp@sha256:abc123... ./integration.sh"
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
