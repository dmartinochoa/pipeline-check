"""CC-019, add_ssh_keys must specify fingerprints."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="CC-019",
    title="`add_ssh_keys` without fingerprint restriction",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-C-SECRET-MGMT",),
    cwe=("CWE-522",),
    recommendation=(
        "Always specify `fingerprints:` when using `add_ssh_keys` to "
        "restrict which SSH keys are loaded into the job. A bare "
        "`add_ssh_keys` step loads ALL project SSH keys."
    ),
    docs_note=(
        "A bare `- add_ssh_keys` step (without `fingerprints:`) loads "
        "every SSH key configured on the project into the job. This "
        "violates least privilege, the job gains access to keys it "
        "does not need, increasing the blast radius if the job is "
        "compromised."
    ),
    exploit_example=(
        "# Vulnerable: ``add_ssh_keys`` with no ``fingerprints``\n"
        "# filter loads every SSH key the project carries into\n"
        "# the agent. Any job in the workflow then uses any key\n"
        "# — a non-deploy job that runs on PR builds has the\n"
        "# production deploy key in scope.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: cimg/base@sha256:abc123...\n"
        "    steps:\n"
        "      - add_ssh_keys\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: pin ``fingerprints`` to the specific key this\n"
        "# job needs. Deploy keys never leak into PR builds; a\n"
        "# leaked PR-job token can't reach the deploy SSH key.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/base@sha256:abc123...\n"
        "    steps:\n"
        "      - add_ssh_keys:\n"
        "          fingerprints:\n"
        "            - \"01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef\"\n"
        "      - run: ./deploy.sh"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unrestricted: list[str] = []
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            # Bare string step: `- add_ssh_keys`
            if isinstance(step, str) and step == "add_ssh_keys":
                unrestricted.append(job_id)
                break
            # Dict step: `- add_ssh_keys:` or `- add_ssh_keys: {fingerprints: [...]}`
            if isinstance(step, dict) and "add_ssh_keys" in step:
                cfg = step["add_ssh_keys"]
                # cfg is None (bare `- add_ssh_keys:`) or a dict
                if not isinstance(cfg, dict) or not cfg.get("fingerprints"):
                    unrestricted.append(job_id)
                    break
    passed = not unrestricted
    desc = (
        "All `add_ssh_keys` steps specify fingerprints, or no "
        "`add_ssh_keys` steps exist."
        if passed else
        f"{len(unrestricted)} job(s) use `add_ssh_keys` without "
        f"fingerprint restriction: {', '.join(unrestricted[:5])}"
        f"{'...' if len(unrestricted) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
