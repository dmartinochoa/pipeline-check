"""GHA-072. Secret surfaced in env: at a wider scope than its consumer.

zizmor ``overprovisioned-secrets``. A secret-bound ``env:`` value
at the job level (``jobs.<id>.env``) is available to every step in
that job's process environment. A workflow-level ``env:`` is
worse, it's available to every step in every job. When only one
step actually consumes the secret, the wider scope is gratuitous
leak surface, any other step that's compromised (action upstream
takeover, ``run:`` injection, cache poisoning) can read the
secret from its own process env.

The fix is to scope the ``env:`` to the smallest enclosing block
that needs the value: the step that uses it.
"""
from __future__ import annotations

import functools
import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-072",
    title="Secret in env: at a wider scope than its consumer",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-5"),
    esf=("ESF-D-SECRETS", "ESF-C-LEAST-PRIV"),
    cwe=("CWE-200", "CWE-272"),
    recommendation=(
        "Move the ``env:`` block carrying the secret to the step "
        "that consumes it. When two or more steps in the same job "
        "need the value, surface it on each step's ``env:`` (or "
        "compute it once via ``echo \"name=...\" >> "
        "$GITHUB_OUTPUT`` from a dedicated minimal step). Avoid "
        "workflow-level ``env:`` for secrets, every job in the "
        "workflow then inherits the value."
    ),
    docs_note=(
        "Fires in two shapes:\n\n"
        "1. **Job-level over-provisioning.** A ``jobs.<id>.env`` "
        "entry's value references ``${{ secrets.* }}`` AND no more "
        "than one step in that job references the env var. The "
        "other steps inherit the secret in their process env "
        "without using it.\n"
        "2. **Workflow-level over-provisioning.** A workflow-level "
        "``env:`` entry's value references ``${{ secrets.* }}`` "
        "AND no more than one job in the workflow references the "
        "env var. The other jobs' processes carry the secret "
        "without using it.\n\n"
        "A step's ``env:`` block at the step level is the safe "
        "default and stays silent. The rule is name-aware: a job "
        "that defines ``DEPLOY_TOKEN`` and ``BUILD_TOKEN`` at the "
        "job level, with only one step using each, fires twice "
        "(one finding per overprovisioned var)."
    ),
    known_fp=(
        "Composite steps that consume the env var internally and "
        "would need ``env:`` block forwarding to see the value "
        "scoped at step level. The local composite-action "
        "discovery path synthesizes those bodies as "
        "``__composite__`` jobs; the env-var reference shows up "
        "there. If it doesn't (a remote composite not loaded by "
        "``--resolve-remote``), suppress per-step via ignore-file "
        "with a note pointing at the composite action.",
    ),
    incident_refs=(
        "zizmor v1.25.2 ``overprovisioned-secrets`` audit: "
        "https://docs.zizmor.sh/audits/#overprovisioned-secrets",
    ),
    exploit_example=(
        "# Vulnerable: ``DEPLOY_TOKEN`` is on the JOB ``env:``,\n"
        "# so every step's process inherits the secret. Only the\n"
        "# ``deploy`` step actually uses it; the ``checkout`` and\n"
        "# ``test`` steps carry the value but don't read it.\n"
        "# Any compromise of those steps can ``env | base64`` to\n"
        "# exfiltrate.\n"
        "jobs:\n"
        "  ship:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./test.sh\n"
        "      - run: |\n"
        "          curl -X POST -H \"Authorization: Bearer "
        "$DEPLOY_TOKEN\" https://api.example.com/deploy\n"
        "\n"
        "# Safe: scope the ``env:`` block to the consuming step.\n"
        "jobs:\n"
        "  ship:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./test.sh\n"
        "      - env:\n"
        "          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
        "        run: |\n"
        "          curl -X POST -H \"Authorization: Bearer "
        "$DEPLOY_TOKEN\" https://api.example.com/deploy"
    ),
)


def _is_secret_binding(value: Any) -> bool:
    """True when *value* references ``${{ secrets.* }}``."""
    return (
        isinstance(value, str)
        and "secrets." in value
        and "${{" in value
    )


def _secret_env_at_level(env_block: Any) -> dict[str, str]:
    """Return ``{var_name: original_value}`` for secret-bound entries."""
    if not isinstance(env_block, dict):
        return {}
    out: dict[str, str] = {}
    for name, value in env_block.items():
        if _is_secret_binding(value):
            out[str(name)] = value
    return out


@functools.cache
def _ref_patterns(name: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Compiled ``(shell, expression)`` reference patterns for *name*.

    Cached by name: the same env-var name is tested against every step
    in a job, so compiling once per distinct name (bounded by the
    workflow's secret-bound env vars) avoids recompiling on every call.
    """
    shell = re.compile(rf"\$(?:\{{{re.escape(name)}\}}|{re.escape(name)}\b)")
    expr = re.compile(rf"\$\{{\{{\s*env\.{re.escape(name)}\s*\}}\}}")
    return shell, expr


def _env_var_reference_count_in_text(name: str, text: str) -> int:
    """Count references to ``$NAME`` / ``${NAME}`` / ``${{ env.NAME }}``.

    Word-bounded to keep ``$TOKEN`` from matching ``$TOKEN_PATH``.
    Both shell forms and the GitHub-Actions expression form
    (``${{ env.NAME }}``) count, since either shape is a real
    consumer of the env binding.
    """
    shell_pattern, expr_pattern = _ref_patterns(name)
    return (
        len(shell_pattern.findall(text)) + len(expr_pattern.findall(text))
    )


def _step_references_env_var(step: dict[str, Any], name: str) -> bool:
    """True when a step's body or with-block references ``$NAME``."""
    run = step.get("run")
    if isinstance(run, str) and _env_var_reference_count_in_text(name, run) > 0:
        return True
    with_block = step.get("with")
    if isinstance(with_block, dict):
        for v in with_block.values():
            if isinstance(v, str) and _env_var_reference_count_in_text(name, v) > 0:
                return True
    # Step-level ``if:`` may carry ``${{ env.NAME }}`` to gate on the
    # secret's presence; that's still a consumer reference.
    if_expr = step.get("if")
    if isinstance(if_expr, str) and _env_var_reference_count_in_text(name, if_expr) > 0:
        return True
    # A step that re-binds the same var on its own ``env:`` is
    # treated as consumer (the operator is explicitly forwarding).
    step_env = step.get("env")
    if isinstance(step_env, dict) and name in step_env:
        return True
    return False


def _job_uses_env_var(job: dict[str, Any], name: str) -> int:
    """Return the number of steps in *job* that reference ``$NAME``."""
    count = 0
    for step in iter_steps(job):
        if _step_references_env_var(step, name):
            count += 1
    return count


def _job_references_workflow_env(
    job: dict[str, Any], name: str,
) -> bool:
    """True if any step in *job* references the workflow-env var."""
    # The job inherits the workflow env. A job that doesn't override
    # the same name is potentially a consumer; we conservatively only
    # count jobs whose steps actually read ``$NAME``.
    # A job-level env that REPLACES the workflow-level var is treated
    # as no inheritance (the workflow var is shadowed).
    job_env = job.get("env")
    if isinstance(job_env, dict) and name in job_env:
        return False
    return _job_uses_env_var(job, name) > 0


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []

    # Workflow-level env over-provisioning
    wf_secret_envs = _secret_env_at_level(doc.get("env"))
    if wf_secret_envs:
        for var_name in wf_secret_envs:
            consumers = sum(
                1
                for _, job in iter_jobs(doc)
                if _job_references_workflow_env(job, var_name)
            )
            if consumers <= 1:
                offenders.append(
                    f"workflow.env.{var_name} (consumed by "
                    f"{consumers} job(s); move to the consuming "
                    f"job's env: or step's env:)"
                )

    # Job-level env over-provisioning
    for job_id, job in iter_jobs(doc):
        job_secret_envs = _secret_env_at_level(job.get("env"))
        for var_name in job_secret_envs:
            consumers = _job_uses_env_var(job, var_name)
            if consumers <= 1:
                offenders.append(
                    f"jobs.{job_id}.env.{var_name} (consumed by "
                    f"{consumers} step(s); move to the consuming "
                    f"step's env:)"
                )

    passed = not offenders
    desc = (
        "No secret-bound env: surfaces at a wider scope than its consumer."
        if passed else
        f"{len(offenders)} secret-bound env: entry(ies) live at a "
        f"wider scope than the steps / jobs that consume them: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. Move each to the "
        f"step (or smallest enclosing block) that needs the value."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
