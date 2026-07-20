"""DR-013. Pipeline defines no trigger event filter."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline

RULE = Rule(
    id="DR-013",
    title="Pipeline defines no trigger event filter",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``trigger:`` block scoping every pipeline to the "
        "events / branches / refs that should run it. The two "
        "high-value patterns are:\n\n"
        "* Trusted-events-only for deploy pipelines:\n\n"
        "    trigger:\n"
        "      event: [push, tag]\n"
        "      branch: [main]\n\n"
        "* Deny-fork-PRs explicitly for credential-handling builds:\n\n"
        "    trigger:\n"
        "      event:\n"
        "        exclude: [pull_request]\n\n"
        "Without ``trigger:``, the pipeline runs on every event "
        "Drone supports (push, pull_request, tag, cron, promotion, "
        "rollback). Pull requests from forks have access to the "
        "pipeline's secret table by default in Drone unless the "
        "repository is marked ``protected`` at the server level; "
        "even with protection, the trigger block is the in-file "
        "audit anchor that survives runner-config drift."
    ),
    docs_note=(
        "Fires when ``trigger:`` is missing from the pipeline "
        "document OR when ``trigger.event`` lists "
        "``pull_request`` without an offsetting "
        "``trigger.event.exclude`` for the same. Pipelines that "
        "explicitly opt into PR builds with secret-handling "
        "gating (``when.event`` per-step + ``protected`` repo "
        "flag) are uncatchable from the YAML alone; suppress per "
        "pipeline with a one-line rationale when the operator "
        "knows the runner configuration.\n\n"
        "Distinct from DR-003 (parameter injection at step "
        "level): this rule audits the pipeline's *event* "
        "trigger surface; DR-003 audits the step's command "
        "substitution surface."
    ),
    known_fp=(
        "Dev / fixture pipelines that intentionally run on "
        "every event (a CI hygiene smoke test, a markdown "
        "linter that's safe on untrusted forks) trip this rule "
        "by design. Suppress per pipeline with a rationale "
        "naming the intentional event scope.",
    ),
    incident_refs=(
        "Drone CI fork-PR token leakage pattern: a pipeline "
        "with no ``trigger:`` runs on pull_request events from "
        "any fork. A malicious contributor opens a PR that "
        "modifies a step to dump ``$DRONE_NETRC_PASSWORD`` (or "
        "any other CI-injected secret) into the build log; the "
        "log is public on Drone's UI; the credential is "
        "harvested.",
    ),
    exploit_example=(
        "# Vulnerable: pipeline runs on every event by default.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: deploy\n"
        "    image: alpine:3.19@sha256:abc...\n"
        "    environment:\n"
        "      DEPLOY_TOKEN: { from_secret: deploy_token }\n"
        "    commands: [./deploy.sh]\n"
        "\n"
        "# Attack: a fork PR modifies ./deploy.sh to log\n"
        "# ${DEPLOY_TOKEN} to stdout. The pipeline runs against\n"
        "# the PR, the secret is injected by Drone, the modified\n"
        "# script logs it; the public build log carries the\n"
        "# token until rotation.\n"
        "\n"
        "# Safe: explicit trigger excludes pull_request.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "trigger:\n"
        "  event:\n"
        "    exclude: [pull_request]\n"
        "  branch: [main]\n"
        "steps:\n"
        "  - name: deploy\n"
        "    image: alpine:3.19@sha256:abc...\n"
    ),
)


def _trigger_includes_pr_without_offset(trigger: Any) -> bool:
    """Return True when ``trigger.event`` includes ``pull_request``
    in the include list without an offsetting exclude."""
    if not isinstance(trigger, dict):
        return False
    event = trigger.get("event")
    if event is None:
        # No ``event`` key (e.g. a ``branch``-only trigger, or ``{}``).
        # Drone's default event scope is *every* event, so PRs — including
        # fork PRs targeting the branch filter — still run the pipeline.
        # This is the same exposure as a missing ``trigger:`` block.
        return True
    # event can be a scalar string, a list, or a dict with
    # ``include`` / ``exclude`` keys.
    include: list[str] = []
    exclude: list[str] = []
    if isinstance(event, str):
        include = [event]
    elif isinstance(event, list):
        include = [e for e in event if isinstance(e, str)]
    elif isinstance(event, dict):
        inc = event.get("include")
        if isinstance(inc, list):
            include = [e for e in inc if isinstance(e, str)]
        elif isinstance(inc, str):
            include = [inc]
        exc = event.get("exclude")
        if isinstance(exc, list):
            exclude = [e for e in exc if isinstance(e, str)]
        elif isinstance(exc, str):
            exclude = [exc]
    if "pull_request" in exclude:
        return False
    if "pull_request" in include:
        return True
    # An include list without pull_request means PRs are denied.
    if include:
        return False
    # No include list and no exclude => every event runs.
    return True


def check(pipeline: Pipeline) -> Finding:
    trigger = pipeline.data.get("trigger")
    name = pipeline.data.get("name", f"doc[{pipeline.doc_index}]")
    if trigger is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline {name!r} has no trigger: block; runs on "
                f"every event (push, pull_request, tag, cron, "
                f"promotion, rollback)."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    if _trigger_includes_pr_without_offset(trigger):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                f"Pipeline {name!r} trigger has no event filter (or its "
                f"``event`` include covers pull_request without an "
                f"offsetting exclude); fork PRs run the pipeline."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path,
        description=(
            f"Pipeline {name!r} trigger scope excludes "
            f"pull_request or defines an explicit event allowlist."
        ),
        recommendation=RULE.recommendation, passed=True,
    )
