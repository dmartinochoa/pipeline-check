"""TAINT-009. Environment-protected secret flows to a job without ``environment:``.

GitHub's environment protection rules (required reviewers, wait timer,
deployment-branch constraints, custom protection rules) only apply to
the job that binds ``environment:``. When that job reads a protected
secret and surfaces it via ``jobs.<id>.outputs:<name>`` to a downstream
job that lacks its own ``environment:`` binding, the downstream job
operates with the secret value but without any of the protection gates.

This bypasses the intent of environment protection: an attacker who
can trigger the workflow (e.g. via a PR event) gets the secret value
in a job that runs without review, wait timers, or branch constraints.

The rule inspects the workflow's ``needs:`` dependency graph, identifies
jobs with ``environment:`` that expose ``${{ secrets.* }}`` through
their ``outputs:`` mapping, and flags any consumer job in the
``needs:`` chain that does not carry its own ``environment:`` binding.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import job_location

RULE = Rule(
    id="TAINT-009",
    title="Environment-protected secret flows to unprotected job",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5", "CICD-SEC-2"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-863",),
    recommendation=(
        "Add an ``environment:`` binding to every job that consumes "
        "outputs carrying secret-derived values. If the downstream "
        "job needs the secret but should not go through the same "
        "review gate, create a separate environment with appropriate "
        "protection rules. Alternatively, restructure the workflow "
        "so the secret never leaves the environment-bound job's "
        "boundary: perform the deploy or credential-consuming "
        "operation in the same protected job instead of passing the "
        "secret through outputs."
    ),
    docs_note=(
        "Detects the pattern where a ``jobs.<id>.outputs:`` mapping "
        "interpolates ``${{ secrets.* }}`` (or a step output that "
        "was populated from a secret) and the producing job has an "
        "``environment:`` binding while at least one consuming job "
        "(via ``needs:``) does not.\n\n"
        "The rule performs a conservative check: it flags when the "
        "output *value expression* directly references "
        "``${{ secrets.* }}`` or when a step output referenced by "
        "the job output was set from a ``${{ secrets.* }}`` context "
        "in the step's ``run:`` or ``env:`` block. Indirect flows "
        "through multiple env-var hops within the same job are not "
        "tracked (the TAINT-002 engine handles general taint "
        "propagation).\n\n"
        "The ``needs:`` graph is walked transitively: if job A "
        "(environment-bound, secret in outputs) feeds job B (no "
        "environment) which feeds job C (no environment), both B "
        "and C are flagged if they reference the tainted output."
    ),
    known_fp=(
        "Workflows that intentionally pass non-sensitive "
        "environment-specific values (e.g. a deployment URL) through "
        "outputs from an environment-bound job. The rule fires on "
        "any ``${{ secrets.* }}`` reference in the output value, "
        "which may include non-sensitive configuration stored in "
        "environment secrets for convenience.",
    ),
    exploit_example=(
        "# Vulnerable: the ``mint`` job reads a production secret\n"
        "# behind an environment gate and passes it to ``deploy``\n"
        "# which has no environment binding.\n"
        "on: push\n"
        "jobs:\n"
        "  mint:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    outputs:\n"
        "      token: ${{ steps.get.outputs.token }}\n"
        "    steps:\n"
        "      - id: get\n"
        "        run: echo \"token=${{ secrets.DEPLOY_TOKEN }}\" >> \"$GITHUB_OUTPUT\"\n"
        "  deploy:\n"
        "    needs: mint\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          curl -H \"Authorization: ${{ needs.mint.outputs.token }}\" https://deploy.example.com\n"
        "\n"
        "# Safe: the deploy job also binds the same environment.\n"
        "on: push\n"
        "jobs:\n"
        "  mint:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    outputs:\n"
        "      token: ${{ steps.get.outputs.token }}\n"
        "    steps:\n"
        "      - id: get\n"
        "        run: echo \"token=${{ secrets.DEPLOY_TOKEN }}\" >> \"$GITHUB_OUTPUT\"\n"
        "  deploy:\n"
        "    needs: mint\n"
        "    environment: production\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          curl -H \"Authorization: ${{ needs.mint.outputs.token }}\" https://deploy.example.com"
    ),
)

_SECRETS_REF_RE = re.compile(
    r"\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
)

_STEP_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*steps\.(?P<step>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)[^}]*\}\}"
)

_GITHUB_OUTPUT_WRITE_RE = re.compile(
    r"""echo\s+(?:-[neE]+\s+)*["']?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)=(?P<val>[^\n]*?)["']?\s*>>?\s*(?:"?\$\{?GITHUB_OUTPUT\}?"?)""",
)

_NEEDS_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*needs\.(?P<job>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)[^}]*\}\}"
)


def _has_environment(job: dict[str, Any]) -> bool:
    return job.get("environment") is not None


def _job_needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs")
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list):
        return [n for n in needs if isinstance(n, str)]
    return []


def _secret_tainted_step_outputs(
    job: dict[str, Any],
) -> set[tuple[str, str]]:
    """Return ``{(step_id, output_name)}`` where the output value derives from a secret."""
    result: set[tuple[str, str]] = set()
    steps = job.get("steps")
    if not isinstance(steps, list):
        return result
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_id = step.get("id")
        if not isinstance(step_id, str):
            continue
        run = step.get("run")
        if not isinstance(run, str):
            continue
        step_env = step.get("env")
        job_env = job.get("env")
        secret_env_names: set[str] = set()
        for env_block in (job_env, step_env):
            if isinstance(env_block, dict):
                for name, val in env_block.items():
                    if isinstance(val, str) and _SECRETS_REF_RE.search(val):
                        secret_env_names.add(name)

        for m in _GITHUB_OUTPUT_WRITE_RE.finditer(run):
            output_name = m.group("name")
            rhs = m.group("val")
            if _SECRETS_REF_RE.search(rhs):
                result.add((step_id, output_name))
            elif secret_env_names:
                for env_name in secret_env_names:
                    if re.search(
                        r"\$\{?" + re.escape(env_name) + r"\}?", rhs,
                    ):
                        result.add((step_id, output_name))
    return result


def _secret_bearing_job_outputs(
    job_id: str, job: dict[str, Any],
) -> set[str]:
    """Return output names from the job that carry secret-derived values."""
    outputs = job.get("outputs")
    if not isinstance(outputs, dict):
        return set()
    tainted_steps = _secret_tainted_step_outputs(job)
    result: set[str] = set()
    for output_name, expression in outputs.items():
        if not isinstance(expression, str):
            continue
        if _SECRETS_REF_RE.search(expression):
            result.add(output_name)
            continue
        for ref_m in _STEP_OUTPUT_REF_RE.finditer(expression):
            ref_step = ref_m.group("step")
            ref_output = ref_m.group("output")
            if (ref_step, ref_output) in tainted_steps:
                result.add(output_name)
    return result


def check(path: str, doc: dict[str, Any]) -> Finding:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No jobs found.",
            recommendation=RULE.recommendation, passed=True,
        )

    env_jobs_with_secret_outputs: dict[str, set[str]] = {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if not _has_environment(job):
            continue
        secret_outputs = _secret_bearing_job_outputs(str(job_id), job)
        if secret_outputs:
            env_jobs_with_secret_outputs[str(job_id)] = secret_outputs

    if not env_jobs_with_secret_outputs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No environment-bound job exposes secret-derived outputs."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations = []

    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if _has_environment(job):
            continue
        needs = _job_needs(job)
        for needed_job in needs:
            if needed_job not in env_jobs_with_secret_outputs:
                continue
            secret_outputs = env_jobs_with_secret_outputs[needed_job]
            job_text = _job_as_text(job)
            for output_name in secret_outputs:
                ref_pattern = (
                    r"needs\." + re.escape(needed_job)
                    + r"\.outputs\." + re.escape(output_name)
                    + r"(?![A-Za-z0-9_-])"
                )
                if re.search(ref_pattern, job_text):
                    ref = f"needs.{needed_job}.outputs.{output_name}"
                    offenders.append(
                        f"{job_id} consumes ``{ref}`` from "
                        f"environment-bound job ``{needed_job}`` "
                        f"without its own ``environment:`` binding"
                    )
                    locations.append(job_location(path, job))
                    break

    passed = not offenders
    if passed:
        desc = (
            "No unprotected job consumes secret-derived outputs from "
            "an environment-bound job."
        )
    else:
        desc = (
            f"{len(offenders)} job(s) bypass environment protection "
            f"rules: {'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. The consuming "
            f"job operates with the secret but without the "
            f"environment's review gates."
        )
    anchor_jobs: dict[str, None] = {}
    for o in offenders:
        anchor_jobs[o.split(" ", 1)[0]] = None
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )


def _job_as_text(job: dict[str, Any]) -> str:
    """Flatten a job dict to a string for reference scanning."""
    import json
    try:
        return json.dumps(job)
    except (TypeError, ValueError):
        return str(job)
