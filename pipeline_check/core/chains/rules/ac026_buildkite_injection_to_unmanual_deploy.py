"""AC-026. Buildkite untrusted-variable injection lands on unmanual deploy.

The Buildkite analog of AC-002 (``GHA-003`` + ``GHA-014``) and
AC-022 (``GL-002`` + ``GL-004``). Every CI provider with a script-
injection primitive and a deploy-gate primitive can compose this
same shape; until now the chain catalog covered GitHub and GitLab
on this surface and left Buildkite as the one provider with both
ingredients but no chain combining them.

The two findings, firing on the same ``pipeline.yml``, compose into
a fork-controllable production push:

- **BK-003.** A step's ``command:`` interpolates an untrusted
  Buildkite variable: a commit subject, branch name, tag, or
  pull-request title. Buildkite expands these (``$BUILDKITE_MESSAGE``,
  ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_PULL_REQUEST_TITLE``)
  before the shell parses the command, so a crafted commit message
  becomes literal shell syntax inside the runner.

- **BK-007.** A deploy-named step (``deploy``, ``release``,
  ``publish``, ``promote``) has no ``manual:`` block and no
  ``input:`` block. The pipeline rolls forward automatically when
  the upstream conditions match.

Combined: anyone who can land a commit on a branch the pipeline
runs against (a fork PR build, a feature branch the runner
auto-deploys from, or a tag push if the deploy step is tag-gated)
supplies the injection vector AND triggers the unattended deploy
in the same run. The injection executes inside the runner with
the deploy step's environment: secrets, AWS / GCP credentials,
Kubernetes contexts, registry push tokens. Exfil or substitute is
trivial; rollback is much harder than refusing the deploy in the
first place.

Each leg has a clean fix that breaks the chain. Quote the
interpolation (or, better, push the untrusted value through a
step env binding so the shell sees a quoted variable) and you
remove the injection regardless of what the deploy step does.
Add ``manual: { prompt: 'Deploy to prod?' }`` (or a separate
``input:`` step) and you require a human to acknowledge the
deploy regardless of what the previous step's command did. Best
is both: defense in depth on the same kill chain.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-026",
    title="Buildkite injection lands on auto-deploy step with no manual gate",
    severity=Severity.CRITICAL,
    summary=(
        "A ``pipeline.yml`` interpolates an untrusted Buildkite "
        "variable (``$BUILDKITE_MESSAGE``, ``$BUILDKITE_BRANCH``, "
        "``$BUILDKITE_PULL_REQUEST_TITLE``, etc.) into a step's "
        "``command:`` body (BK-003) AND a deploy-named step in the "
        "same pipeline runs without a ``manual:`` or ``input:`` "
        "gate (BK-007). The combination converts a fork-controllable "
        "injection point into an unattended production push, the "
        "Buildkite analog of AC-002 / AC-022 on the GitHub and "
        "GitLab surfaces."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1078",      # Valid Accounts (deploy creds)
        "T1556",      # Modify Authentication Process
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://buildkite.com/docs/pipelines/environment-variables",
        "https://buildkite.com/docs/pipelines/block-step",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms",
    ),
    recommendation=(
        "On the injection side: stop interpolating Buildkite "
        "metadata variables directly into ``command:`` bodies. "
        "Bind the value through ``env:`` instead "
        "(``env: { MSG: \"$BUILDKITE_MESSAGE\" }`` then reference "
        "``\"$MSG\"`` inside the command) so the shell sees a "
        "quoted variable rather than syntax it can interpret. On "
        "the gate side: every deploy-named step should carry a "
        "``manual:`` block (or be preceded by a separate "
        "``input:`` step) so a human reviewer acknowledges the "
        "deploy. Configure the manual block's ``branches:`` filter "
        "and the surrounding step's ``branches:`` filter together "
        "so a fork PR build can't trigger production. Either fix "
        "breaks the chain; both is best."
    ),
    providers=("buildkite",),
    triggering_check_ids=("BK-003", "BK-007"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["BK-003", "BK-007"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["BK-003"], ck_map["BK-007"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A step's ``command:`` interpolates an untrusted "
            "Buildkite variable (BK-003): commit subject, branch "
            "name, tag name, or pull-request title. Buildkite "
            "expands these before the shell parses the command, so "
            "a crafted commit message becomes literal shell syntax "
            "inside the runner.\n"
            "  2. A deploy-named step in the same pipeline has no "
            "``manual:`` or ``input:`` gate (BK-007). The pipeline "
            "rolls forward automatically when its upstream "
            "conditions match.\n"
            "  3. Combined: anyone who can land a commit on a "
            "branch this pipeline builds, fork-PR builds, feature "
            "branches the runner auto-deploys from, supplies the "
            "injection vector AND triggers the unattended deploy "
            "in the same run. The injected command executes with "
            "the deploy step's secrets and credentials. Quote the "
            "interpolation (or push it through ``env:``) AND add "
            "a ``manual:`` block to the deploy step; either fix "
            "breaks the chain, both is best."
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
            triggering_check_ids=["BK-003", "BK-007"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
