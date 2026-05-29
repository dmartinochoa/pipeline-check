"""GHA-108. Sensitive workflow has no runtime egress control.

A static scan can read the workflow YAML, but it can't see what a
dependency or action *does* at runtime. The attack class harden-runner
exists to close, a compromised package or action that phones home and
exfiltrates the runner's credentials, is invisible to a config
scanner. The defense-in-depth answer is a runtime egress allowlist.

This advisory fires when a workflow has credentials worth stealing,
an OIDC token (`id-token: write`) or a job gated on a deployment
`environment:`, and no job uses an egress-control agent
(step-security/harden-runner). It's deliberately scoped to those two
high-value, low-volume signals rather than "any job that touches a
secret" so the advisory stays targeted. Severity is LOW: plenty of
teams accept this risk or enforce egress at the network layer, which
the YAML can't express.

Pairs with GHA-107 (harden-runner present but in audit mode). The two
are mutually exclusive by construction: GHA-108 only fires when no
harden-runner step exists anywhere in the workflow.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, job_location

_HARDEN_RUNNER = "step-security/harden-runner"

RULE = Rule(
    id="GHA-108",
    title="Sensitive workflow has no runtime egress control",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7", "CICD-SEC-10"),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-693",),  # Protection Mechanism Failure
    recommendation=(
        "Add step-security/harden-runner as the first step of jobs that "
        "authenticate via OIDC or deploy through a protected "
        "environment, and set `egress-policy: block` with an "
        "`allowed-endpoints` allowlist. A static scan can't see what a "
        "compromised dependency or action does at runtime; an egress "
        "allowlist is the defense-in-depth layer that stops it from "
        "shipping the OIDC credential or deploy secret off the runner. "
        "If egress is already constrained at the network layer "
        "(self-hosted runners behind a firewall or forward proxy), "
        "suppress this advisory with that rationale."
    ),
    docs_note=(
        "Advisory rule. Fires when a workflow mints an OIDC token "
        "(`id-token: write`, at workflow or job scope) or gates a job "
        "on a deployment `environment:`, AND no job in the workflow "
        "uses an egress-control agent (step-security/harden-runner). "
        "Those are the jobs with credentials worth stealing and no "
        "runtime guard against a dependency or action exfiltrating "
        "them.\n\n"
        "Scoped deliberately to OIDC and environment-gated jobs to keep "
        "the signal targeted; it does not fire on every job that merely "
        "references a secret. Severity is LOW because many teams accept "
        "this risk or enforce egress at the infrastructure layer, which "
        "the workflow YAML can't express."
    ),
    known_fp=(
        "Egress controlled outside the workflow (self-hosted runners "
        "behind a firewall or forward proxy, an org-wide network "
        "policy) gives the same protection without a harden-runner "
        "step. The scanner only sees the YAML, so it fires anyway. "
        "Suppress with a rationale naming the external control.",
        "A workflow that uses OIDC only to read public data, or an "
        "environment with no real secrets, carries less exfiltration "
        "risk. Suppress per-workflow.",
    ),
    incident_refs=(
        "StepSecurity, tj-actions/changed-files compromise (2025): a "
        "popular action was backdoored to exfiltrate CI secrets over "
        "the network. A runtime egress allowlist drops the connection "
        "the payload depends on. "
        "https://www.stepsecurity.io/blog/popular-github-action-"
        "tj-actions-changed-files-is-compromised",
    ),
    exploit_example=(
        "# Vulnerable: the job assumes a cloud role via OIDC and runs a\n"
        "# build with third-party dependencies, with nothing watching\n"
        "# the network. A compromised dependency reads the OIDC token\n"
        "# from the runner and exfiltrates it.\n"
        "on: push\n"
        "permissions:\n"
        "  id-token: write\n"
        "  contents: read\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci\n"
        "      - uses: aws-actions/configure-aws-credentials@<sha>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::111122223333:role/deploy\n"
        "          aws-region: us-east-1\n"
        "      - run: npm run deploy\n"
        "\n"
        "# Safe: harden-runner runs first in block mode, so any\n"
        "# connection to a host outside the allowlist is dropped before\n"
        "# the OIDC token can leave the runner.\n"
        "on: push\n"
        "permissions:\n"
        "  id-token: write\n"
        "  contents: read\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: step-security/harden-runner@<sha>\n"
        "        with:\n"
        "          egress-policy: block\n"
        "          allowed-endpoints: >\n"
        "            github.com:443\n"
        "            registry.npmjs.org:443\n"
        "            sts.us-east-1.amazonaws.com:443\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci\n"
        "      - uses: aws-actions/configure-aws-credentials@<sha>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::111122223333:role/deploy\n"
        "          aws-region: us-east-1\n"
        "      - run: npm run deploy"
    ),
)


def _uses_harden_runner(doc: dict[str, Any]) -> bool:
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            uses = step.get("uses")
            if isinstance(uses, str) and (
                uses.split("@", 1)[0].strip().lower() == _HARDEN_RUNNER
            ):
                return True
    return False


def _has_oidc(perms: Any) -> bool:
    """True when a permissions block grants ``id-token: write``."""
    if isinstance(perms, str):
        return perms.strip().lower() == "write-all"
    if isinstance(perms, dict):
        val = perms.get("id-token")
        return isinstance(val, str) and val.strip().lower() == "write"
    return False


def _sensitive_jobs(
    doc: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    """Jobs that mint an OIDC token or deploy through an environment.

    A job's own ``permissions:`` wins; only when it's absent does the
    workflow-level block apply (GitHub's runtime semantics).
    """
    top_perms = doc.get("permissions")
    out: list[tuple[str, dict[str, Any]]] = []
    for job_id, job in iter_jobs(doc):
        own = job.get("permissions")
        effective = own if own is not None else top_perms
        if _has_oidc(effective) or job.get("environment") is not None:
            out.append((job_id, job))
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    if _uses_harden_runner(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow uses an egress-control agent "
                "(step-security/harden-runner)."
            ),
            recommendation="No action required.", passed=True,
        )

    sensitive = _sensitive_jobs(doc)
    if not sensitive:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No OIDC or environment-gated job to protect with an "
                "egress allowlist."
            ),
            recommendation="No action required.", passed=True,
        )

    job_ids = [jid for jid, _ in sensitive]
    locations = [job_location(path, job) for _, job in sensitive]
    desc = (
        f"{len(job_ids)} job(s) mint OIDC tokens or deploy through a "
        f"protected environment with no runtime egress control: "
        f"{', '.join(job_ids[:5])}"
        f"{'...' if len(job_ids) > 5 else ''}. A compromised dependency "
        f"or action in these jobs can exfiltrate the OIDC credential or "
        f"deploy secret with nothing at the network layer to stop it."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
        job_anchors=tuple(job_ids),
    )
