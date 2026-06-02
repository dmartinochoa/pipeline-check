"""CC-019, add_ssh_keys must specify fingerprints."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

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


def _iter_steps_recursive(
    steps: list[Any],
) -> Iterator[dict[str, Any] | str]:
    """Yield every step, recursing into ``when:``/``unless:`` sub-step lists."""
    for step in steps:
        yield step
        if isinstance(step, dict):
            for key in ("when", "unless"):
                sub = step.get(key)
                if isinstance(sub, dict):
                    inner = sub.get("steps")
                    if isinstance(inner, list):
                        yield from _iter_steps_recursive(inner)


def _bare_add_ssh_keys_in_steps(steps: list[Any]) -> bool:
    """Return True if any step (recursively) is a fingerprint-less add_ssh_keys."""
    for step in _iter_steps_recursive(steps):
        if isinstance(step, str) and step == "add_ssh_keys":
            return True
        if isinstance(step, dict) and "add_ssh_keys" in step:
            cfg = step["add_ssh_keys"]
            if not isinstance(cfg, dict) or not cfg.get("fingerprints"):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    unrestricted: list[str] = []

    # Scan top-level job steps (including when:/unless: sub-steps).
    for job_id, job in iter_jobs(doc):
        raw_steps = job.get("steps") or []
        if isinstance(raw_steps, list) and _bare_add_ssh_keys_in_steps(raw_steps):
            unrestricted.append(job_id)

    # Scan top-level reusable commands block.
    commands = doc.get("commands") or {}
    if isinstance(commands, dict):
        for cmd_id, cmd_def in commands.items():
            if not isinstance(cmd_def, dict):
                continue
            raw_steps = cmd_def.get("steps") or []
            if isinstance(raw_steps, list) and _bare_add_ssh_keys_in_steps(raw_steps):
                unrestricted.append(f"commands/{cmd_id}")

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
