"""GL-040. CI_JOB_TOKEN used to authenticate to another project / remote."""
from __future__ import annotations

import re
from typing import Any

from ...base import Confidence, Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

# ``git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@host/group/project.git``
# embeds the ambient job token as the clone credential, the documented
# cross-project pull idiom.
_CLONE_TOKEN_RE = re.compile(
    r"gitlab-ci-token:\s*\$\{?CI_JOB_TOKEN\}?@", re.IGNORECASE
)
# ``curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://host/api/v4/projects/...``
# authenticates to the REST API with the job token.
_HEADER_TOKEN_RE = re.compile(
    r"JOB-TOKEN:\s*[\"']?\$\{?CI_JOB_TOKEN\}?", re.IGNORECASE
)

RULE = Rule(
    id="GL-040",
    title="CI_JOB_TOKEN used for cross-project / remote access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-668", "CWE-284"),
    recommendation=(
        "A job authenticates to a GitLab endpoint with the ambient "
        "``CI_JOB_TOKEN`` (a ``gitlab-ci-token:$CI_JOB_TOKEN@`` clone "
        "URL or a ``JOB-TOKEN: $CI_JOB_TOKEN`` API header). The job "
        "token is minted automatically for every pipeline, so if the "
        "TARGET project's inbound job-token allowlist is disabled (the "
        "pre-hardening default), any project that can run a pipeline "
        "can reach it (GitLab #243703 / CVE-2024-8641). Restrict the "
        "target's ``CI/CD > Token Access`` inbound allowlist to the "
        "specific projects that need it, or use a scoped deploy token "
        "/ project access token with least privilege instead of the "
        "ambient job token."
    ),
    docs_note=(
        "Fires on the two documented cross-project job-token idioms in "
        "a ``script:`` / ``before_script:`` / ``after_script:`` block: "
        "a ``gitlab-ci-token:$CI_JOB_TOKEN@<host>`` clone URL, or a "
        "``JOB-TOKEN: $CI_JOB_TOKEN`` request header. Defaults to "
        "MEDIUM confidence because a same-project pull uses the same "
        "idiom; the finding flags the access surface so the target's "
        "inbound allowlist gets reviewed, it can't see the server-side "
        "allowlist from the pipeline YAML."
    ),
    exploit_example=(
        "# Vulnerable: the job token reaches a DIFFERENT project.\n"
        "pull-internal-libs:\n"
        "  script:\n"
        "    - git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/platform/internal-libs.git\n"
        "    - curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" https://gitlab.example.com/api/v4/projects/4242/packages\n"
        "\n"
        "# Attack: if platform/internal-libs has 'allow access from all\n"
        "# projects' set, any attacker-controlled project's pipeline mints\n"
        "# its own job token and reads / clones the target.\n"
        "\n"
        "# Safe: a scoped deploy token, and restrict the target's inbound\n"
        "# CI/CD job-token allowlist to the projects that need it.\n"
        "pull-internal-libs:\n"
        "  script:\n"
        "    - git clone https://gitlab-deploy-token:${LIBS_DEPLOY_TOKEN}@gitlab.example.com/platform/internal-libs.git"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        body = "\n".join(job_scripts(job))
        if not body:
            continue
        if _CLONE_TOKEN_RE.search(body):
            offenders.append(f"{name}: gitlab-ci-token:$CI_JOB_TOKEN@ clone")
        if _HEADER_TOKEN_RE.search(body):
            offenders.append(f"{name}: JOB-TOKEN: $CI_JOB_TOKEN header")
    passed = not offenders
    desc = (
        "No job authenticates to another project with CI_JOB_TOKEN."
        if passed else
        f"{len(offenders)} use(s) of CI_JOB_TOKEN for cross-project / "
        f"remote access: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        confidence=Confidence.HIGH if passed else Confidence.MEDIUM,
    )
