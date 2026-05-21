"""DF-012, ``sudo`` invocation inside a ``RUN``."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-012",
    title="RUN invokes sudo",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Drop ``sudo`` from the ``RUN``. Either the build is already "
        "running as root (the default before any ``USER`` directive), "
        "in which case ``sudo`` is no-op noise, or the build switched "
        "to a non-root ``USER`` and needs root for a specific step, "
        "in which case temporarily revert with ``USER root`` for that "
        "``RUN`` and switch back afterward."
    ),
    docs_note=(
        "``sudo`` inside a Dockerfile is almost always a copy-paste "
        "from a host README. Its presence usually means one of three "
        "things, all of them wrong: (a) the build is silently running "
        "as root and the operator misread it, (b) the image carries "
        "an unrestricted ``sudoers`` line that a runtime escape can "
        "abuse, or (c) the package install chain depends on TTY-aware "
        "``sudo`` behavior that breaks under non-TTY ``docker build``. "
        "None of these cases benefit from keeping the directive."
    ),
    exploit_example=(
        "# Vulnerable: ``RUN sudo apt-get install -y curl`` requires\n"
        "# the image to ship sudo (extra attack surface) AND runs\n"
        "# as a non-root user that has sudo rights. A compromise\n"
        "# at runtime can ``sudo`` to root inside the container,\n"
        "# defeating the non-root-user posture.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "RUN apt-get update && apt-get install -y sudo curl\n"
        "RUN useradd -m app && adduser app sudo\n"
        "USER app\n"
        "RUN sudo apt-get install -y jq    # privilege escalation primitive in image\n"
        "\n"
        "# Safe: do every privileged step BEFORE the ``USER``\n"
        "# directive, while still root. Drop sudo from the image\n"
        "# entirely. The final ``USER app`` runs without any path\n"
        "# back to root.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "RUN apt-get update \\\n"
        "    && apt-get install -y curl jq \\\n"
        "    && useradd -m app \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
        "USER app"
    ),
)

# Word-boundary match so ``pseudo``, ``sudoers``, ``Sudokugame`` don't
# trigger. Allow leading ``-E`` / ``-H`` flag forms and a typical
# ``sudo command`` shape, but not ``visudo`` (that's the editor for
# the sudoers file itself, which is a legitimate package-config use).
_SUDO_RE = re.compile(r"(?:^|[\s|;&])sudo(?:\s+-?\w+)*\s+\S", re.MULTILINE)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, body in run_bodies(df):
        if _SUDO_RE.search(body):
            offenders.append(f"L{line_no}")
    passed = not offenders
    desc = (
        "No ``RUN`` body invokes ``sudo``."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies invoke ``sudo``: "
        f"{', '.join(offenders)}. Drop ``sudo`` and run the underlying "
        f"command directly under whatever ``USER`` the layer needs."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
