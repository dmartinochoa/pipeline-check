"""GL-044. Automatic production deployment on a merge-request pipeline."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import PROD_ENV_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import job_runs_on_mr, rules_manual

RULE = Rule(
    id="GL-044",
    title="Automatic production deployment on a merge-request pipeline",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Don't run a job bound to a production `environment:` "
        "automatically on a merge-request pipeline. A merge-request "
        "pipeline runs the MR branch's code, so this ships unreviewed "
        "(and on fork MRs, untrusted) changes to production on every MR "
        "with the production environment's scoped credentials, before "
        "review or merge. Deploy to an ephemeral review-app environment "
        "on MRs; gate the production `environment:` job behind "
        "`when: manual` and a protected-branch rule "
        "(`if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`) so it runs "
        "against merged, reviewed code."
    ),
    docs_note=(
        "Fires when a job reachable on a merge-request pipeline (its "
        "`rules:` admit `merge_request_event`, its legacy `only:` "
        "includes `merge_requests`, or it inherits a `workflow:` that "
        "admits MR pipelines) binds a production-tier `environment:` "
        "(a name matching `production` / `prod`) AND is not gated by "
        "`when: manual`. GL-004 treats any `environment:` as sufficient "
        "gating, so it misses an automatic production deploy on an MR; "
        "GL-044 names that shape and raises it to CRITICAL. Review-app, "
        "`test`, and `staging` environments don't fire (only the "
        "production tier), manual-approval jobs are out of scope "
        "(GitLab's accepted gate), and an `environment:` `action:` of "
        "`stop` / `prepare` / `verify` / `access` (no deploy) is "
        "excluded."
    ),
    known_fp=(
        "A repo that deploys per-MR preview apps to an environment it "
        "happens to have named `production`. Rename it to a review / "
        "preview tier, or suppress with a rationale. A production "
        "environment under a custom name (not `production` / `prod`) "
        "can't be recognized from the YAML and won't fire.",
    ),
    exploit_example=(
        "# Vulnerable: every merge request auto-deploys to production.\n"
        "deploy_prod:\n"
        "  stage: deploy\n"
        "  environment: production\n"
        "  script:\n"
        "    - ./deploy.sh\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
        "\n"
        "# Attack: a contributor opens an MR that edits deploy.sh (or any\n"
        "# earlier build step); the MR pipeline runs it with the\n"
        "# production environment's credentials and ships the change live\n"
        "# before review. GL-004 stays silent because the job has an\n"
        "# `environment:`.\n"
        "\n"
        "# Safe: MRs deploy a review app; production is manual + protected.\n"
        "deploy_review:\n"
        "  stage: deploy\n"
        "  environment:\n"
        "    name: review/$CI_COMMIT_REF_SLUG\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
        "deploy_prod:\n"
        "  stage: deploy\n"
        "  environment: production\n"
        "  rules:\n"
        "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n"
        "      when: manual"
    ),
)


def _deploy_env_name(environment: Any) -> str | None:
    """Return the environment name when *environment* is a deploy binding.

    Handles both the scalar (`environment: production`) and the mapping
    (`environment: { name: production, action: start }`) forms. A
    non-`start` `action:` (`stop` / `prepare` / `verify` / `access`)
    doesn't deploy code, so it returns ``None``.
    """
    if isinstance(environment, str):
        return environment
    if isinstance(environment, dict):
        action = environment.get("action")
        if isinstance(action, str) and action != "start":
            return None
        name = environment.get("name")
        return name if isinstance(name, str) else None
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        if not job_runs_on_mr(doc, job):
            continue
        env_name = _deploy_env_name(job.get("environment"))
        if env_name is None or not PROD_ENV_RE.match(env_name.strip()):
            continue
        # Manual approval is GitLab's accepted deploy gate (GL-004 treats
        # it as such), so a manually-triggered prod deploy is out of scope.
        manual = job.get("when") == "manual" or rules_manual(job.get("rules"))
        if manual:
            continue
        offenders.append(name)
    passed = not offenders
    desc = (
        "No merge-request-reachable job auto-deploys to production."
        if passed else
        f"{len(offenders)} job(s) auto-deploy to a production "
        f"`environment:` on a merge-request pipeline: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The MR branch's code "
        f"ships to production with the environment's scoped credentials, "
        f"before the change is reviewed or merged."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
