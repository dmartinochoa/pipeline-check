"""CC-017, docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from ..._primitives.blob_rule import yaml_blob_check
from ...base import DOCKER_INSECURE_RE, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-017",
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
        "host-root volume mounts (`-v /:/`) in a CircleCI config give "
        "the container full access to the runner, enabling container "
        "escape and lateral movement."
    ),
    exploit_example=(
        "# Vulnerable: ``docker run --privileged`` plus the host\n"
        "# Docker socket gives the build container full kernel\n"
        "# access and the agent's Docker runtime. A compromise\n"
        "# escapes to the agent and from there to every other\n"
        "# build sharing it.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  integration:\n"
        "    machine:\n"
        "      image: ubuntu-2204:2024.01.1\n"
        "    steps:\n"
        "      - run: |\n"
        "          docker run --privileged \\\n"
        "            -v /var/run/docker.sock:/var/run/docker.sock \\\n"
        "            myapp:test ./integration.sh\n"
        "\n"
        "# Safe: drop ``--privileged`` and the socket mount. If\n"
        "# the build genuinely needs to build images, use a\n"
        "# rootless sandbox (Kaniko, BuildKit rootless) instead.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  integration:\n"
        "    docker:\n"
        "      - image: myapp:test@sha256:abc123...\n"
        "    steps:\n"
        "      - run: ./integration.sh"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=DOCKER_INSECURE_RE.findall,
    pass_desc="No insecure docker run flags detected in this config.",
    fail_desc=lambda matches: (
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    ),
)
