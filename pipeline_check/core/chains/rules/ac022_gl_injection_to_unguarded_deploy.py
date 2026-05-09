"""AC-022. GitLab CI script injection lands on a deploy job with no
manual approval or environment gate.

The GitLab analog of AC-002 (the GHA ``script-injection +
unprotected-deploy`` chain). Two findings each individually wrong
become an end-to-end CI takeover when they fire on the same
``.gitlab-ci.yml``:

- **GL-002.** A job's ``script:`` interpolates an attacker-influenced
  field (``$CI_COMMIT_TITLE``, ``$CI_COMMIT_DESCRIPTION``,
  ``$CI_MERGE_REQUEST_TITLE``, or a branch / tag name). Any of these
  reach the runner shell unsanitized, so a fork-MR author who
  controls the field controls the command line.

- **GL-004.** A deploy job (``deploy:``, ``stage: deploy``,
  ``environment:`` set to a prod-like name) runs without a manual
  approval (``when: manual``), without ``environment.deployment_tier:
  production`` + protected branches, and without ``rules:`` /
  ``only:`` that limit it to the default branch. The job ships
  whatever artifacts the upstream stages produced, on every
  successful pipeline.

Combined: a fork MR (or a push to any branch the pipeline runs on)
that crafts a malicious commit title injects a shell command into
the build stage's runner, which writes its payload into the
artifacts the deploy stage consumes, and the deploy stage runs
unattended. The runner's ``CI_JOB_TOKEN`` plus whatever deploy
secrets the job needs (cloud provider keys, kube configs,
container-registry credentials) become attacker-controlled with
no human in the loop.

Each leg has a fix that breaks the chain: switch the
``$CI_COMMIT_*`` interpolation to a quoted ``CI_*`` env-var
reference (``echo "$TITLE"`` where ``variables: TITLE:
$CI_COMMIT_TITLE``) or move the deploy job behind ``when: manual``
+ a protected ``environment:``. Both is best.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-022",
    title="GitLab script injection lands on deploy job with no manual gate",
    severity=Severity.CRITICAL,
    summary=(
        "A ``.gitlab-ci.yml`` job interpolates an attacker-controlled "
        "context field directly into its ``script:`` (GL-002) AND a "
        "deploy job in the same file lacks a manual approval / "
        "protected ``environment:`` gate (GL-004). A crafted commit "
        "title or MR description from any branch the pipeline runs "
        "on injects a shell command into the build stage; the "
        "deploy stage then ships the resulting artifacts to "
        "production unattended."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1078",      # Valid Accounts
        "T1556",      # Modify Authentication Process
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        "https://docs.gitlab.com/ee/ci/environments/protected_environments.html",
        "https://docs.gitlab.com/ee/ci/yaml/#whenmanual",
        "https://docs.gitlab.com/ee/ci/variables/predefined_variables.html",
    ),
    recommendation=(
        "On the injection side: never interpolate ``$CI_COMMIT_*`` / "
        "``$CI_MERGE_REQUEST_*`` directly into a shell command. "
        "Bind the field to a job-scoped ``variables:`` entry and "
        "reference the variable inside double quotes (``echo "
        "\"$TITLE\"``), so the shell sees one literal argument "
        "rather than interpreted syntax. On the deploy side: gate "
        "every job that publishes artifacts, applies infrastructure, "
        "or pushes to a registry behind ``when: manual`` plus an "
        "``environment:`` mapped to a *protected* environment in "
        "GitLab settings, and use ``rules:``/``only:`` to limit the "
        "job to the default branch. Either fix breaks the chain; "
        "doing both also closes off the same primitive against "
        "future rule additions."
    ),
    providers=("gitlab",),
    triggering_check_ids=("GL-002", "GL-004"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GL-002", "GL-004"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GL-002"], ck_map["GL-004"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A job's ``script:`` interpolates an attacker-"
            "controlled GitLab context field (a commit title, MR "
            "description, branch name, or similar) (GL-002). The "
            "field reaches the runner's shell unsanitized, so a "
            "crafted commit message becomes a shell command in the "
            "build stage.\n"
            "  2. A deploy job in the same file has no ``when: "
            "manual`` approval and no protected ``environment:`` "
            "binding (GL-004). GitLab's protected-environment "
            "rules (required reviewers, deployment-branch "
            "restrictions, manual approval) only apply to jobs "
            "that opt in, so this job ships whatever the upstream "
            "stages produced on every successful pipeline.\n"
            "  3. Together: the injection in stage 1 modifies the "
            "artifacts (or env / config) that stage 2 consumes, "
            "and stage 2 deploys without a human in the loop. The "
            "runner's ``CI_JOB_TOKEN`` plus the deploy job's "
            "production secrets execute attacker-controlled "
            "behavior. Quote the interpolation through a "
            "``variables:`` indirection or move the deploy behind "
            "``when: manual``. Either breaks the chain."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GL-002", "GL-004"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
