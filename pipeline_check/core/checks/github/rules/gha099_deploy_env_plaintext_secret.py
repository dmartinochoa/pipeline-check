"""GHA-099. Deploy job sets a secret-shaped value as a plaintext env var."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import DEPLOY_RE as _DEPLOY_NAME_RE
from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, job_location

RULE = Rule(
    id="GHA-099",
    title="Deployment job has a secret-shaped plaintext env var",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-2"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Move the credential to an encrypted repository or environment "
        "secret and reference it via ``${{ secrets.NAME }}``. For "
        "cloud access, prefer OIDC federation (``id-token: write`` + "
        "the provider's configure-credentials action) over any static "
        "key. A plaintext credential in a deploy job is doubly "
        "dangerous: it's visible in every fork and build log AND it "
        "has production-level blast radius."
    ),
    docs_note=(
        "Complements GHA-008 (credential-shaped literal anywhere in "
        "a workflow) by focusing on the deploy-job subset with an "
        "elevated severity rationale. GHA-008 fires on every "
        "credential literal; GHA-099 fires only when the literal "
        "appears in a job that also has an ``environment:`` binding "
        "or whose name / id matches a deploy / release / publish "
        "pattern. The overlap is intentional: the deploy context "
        "raises the blast radius from 'CI runner compromise' to "
        "'production compromise', justifying a distinct finding "
        "in the report.\n\n"
        "Detection reuses the same credential-pattern catalog as "
        "GHA-008 (``find_secret_values``), scoped to the ``env:`` "
        "block of the deploy job and its steps."
    ),
    known_fp=(
        "Test fixtures with example credentials (``AKIAIOSFODNN7"
        "EXAMPLE``) in a deploy-named job will fire. Suppress with "
        "a rationale confirming the value is a non-functional "
        "example.",
    ),
    exploit_example=(
        "# Vulnerable: a deploy job carries a production AWS key\n"
        "# as a plaintext env var instead of a secrets reference.\n"
        "jobs:\n"
        "  deploy-prod:\n"
        "    environment: production\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      AWS_ACCESS_KEY_ID: AKIAI44QH8DHBEXAMPLE\n"
        "      AWS_SECRET_ACCESS_KEY: wJalrXUt/K7MDENG/bPxRfiCYEXAMPLE\n"
        "    steps:\n"
        "      - run: aws ecs update-service --force-new-deployment\n"
        "\n"
        "# Safe: reference encrypted secrets; better still, use OIDC.\n"
        "jobs:\n"
        "  deploy-prod:\n"
        "    environment: production\n"
        "    permissions: { id-token: write }\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<sha>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123456789012:role/CIRole\n"
        "          aws-region: us-east-1"
    ),
)

def _is_deploy_job(job_id: str, job: dict[str, Any]) -> bool:
    if job.get("environment") is not None:
        return True
    if isinstance(job_id, str) and _DEPLOY_NAME_RE.search(job_id):
        return True
    name = job.get("name")
    return isinstance(name, str) and bool(_DEPLOY_NAME_RE.search(name))


def _collect_env_block(block: Any) -> dict[str, Any]:
    if isinstance(block, dict):
        return block
    return {}


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []

    for job_id, job in iter_jobs(doc):
        if not _is_deploy_job(job_id, job):
            continue

        job_env = _collect_env_block(job.get("env"))
        step_envs: list[dict[str, Any]] = []
        for step in iter_steps(job):
            step_envs.append(_collect_env_block(step.get("env")))

        all_env_values: list[str] = []
        for v in job_env.values():
            if isinstance(v, str):
                all_env_values.append(v)
        for senv in step_envs:
            for v in senv.values():
                if isinstance(v, str):
                    all_env_values.append(v)

        if not all_env_values:
            continue

        hits = find_secret_values(all_env_values)
        if hits:
            offenders.append(
                f"{job_id}: {', '.join(hits[:3])}"
                f"{'...' if len(hits) > 3 else ''}"
            )
            locations.append(job_location(path, job))

    passed = not offenders
    if passed:
        desc = (
            "No deploy / environment-gated jobs contain credential-"
            "shaped plaintext env vars."
        )
    else:
        desc = (
            f"{len(offenders)} deploy job(s) carry credential-shaped "
            f"plaintext in their env blocks: "
            f"{'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. "
            f"These values are visible in every fork and build log "
            f"and carry production-level blast radius."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
