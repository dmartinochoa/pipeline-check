"""GHA-004, workflow must declare an explicit `permissions:` block.

Six firing conditions:

1. **Missing block.** No top-level ``permissions:`` and at least one
   job without its own block.
2. **``write-all`` overly broad.** Either top-level or job-level.
3. **``contents: write`` on a pull_request workflow.** Specific
   PR-triggered foot-gun.
4. **``id-token: write`` without an OIDC consumer step.** Detected
   via ``_is_oidc_step``.
5. **Other write scope granted but no step consumes it.** Generalized
   overprovisioning detection: for each write scope in the
   ``_SCOPE_CONSUMERS_*`` maps, walk the job's steps for an action
   or ``run:`` shape that justifies the grant. Wildcard consumers
   (``actions/github-script``) treat every scope as consumed.
6. **Top-level write scope not consumed by any inheriting job.**
   Aggregates across all jobs that inherit the workflow-level
   permissions (no job-level override, not a reusable-workflow
   caller). A top-level write grant that no inheriting job
   consumes is excess privilege on every job that inherits it.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Workflow, iter_jobs, iter_steps, workflow_triggers

RULE = Rule(
    id="GHA-004",
    title="Workflow permissions block missing or overprovisioned",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Add a top-level `permissions:` block (start with `contents: "
        "read`) and grant additional scopes only on the specific jobs "
        "that need them. For job-level blocks, prune any write scope "
        "no step in the job actually uses, the rule names the "
        "specific scopes the job's steps don't justify."
    ),
    docs_note=(
        "Without an explicit `permissions:` block (either top-level "
        "or per-job), the GITHUB_TOKEN inherits the repository's "
        "default scope, typically `write`. A compromised step "
        "receives far more privilege than it needs.\n\n"
        "Beyond the missing-block case, the rule also flags "
        "over-grants: a job that declares ``packages: write`` but "
        "never runs ``docker push`` / ``npm publish`` / "
        "``gh release upload``, a job that declares ``issues: "
        "write`` but never calls ``gh issue ...``, a job that "
        "declares ``security-events: write`` but never invokes a "
        "SARIF uploader, etc. Wildcard consumers "
        "(``actions/github-script``) suppress the flag because "
        "they can reach any scope through the GitHub API.\n\n"
        "The rule also aggregates at the workflow level: when a "
        "top-level ``permissions:`` block grants a write scope "
        "that no inheriting job (a job without its own permissions "
        "override) actually consumes, the workflow is handing "
        "every inheriting job more privilege than its steps need. "
        "Move the scope to the specific job that needs it, or "
        "drop it entirely."
    ),
    known_fp=(
        "Read-only / lint-only workflows that do not call any "
        "write-scoped API often pass without an explicit block "
        "because the default token scope on public repos is read. "
        "The rule defaults to MEDIUM confidence to reflect this. "
        "For the overprovisioned-scope case, false positives can "
        "appear when a workflow consumes a scope through a third-"
        "party action this rule's consumer list doesn't recognize "
        "yet, file an issue to extend the catalog when discovered.",
    ),
)


def _is_write_all(perms: Any) -> bool:
    """True if permissions is the string ``write-all``."""
    return isinstance(perms, str) and perms.strip().lower() == "write-all"


#: Action prefixes that legitimately consume ``id-token: write``. Each
#: entry is matched as a substring against the step's ``uses:`` value
#: so version pins and digest pins both match.
_OIDC_ACTION_PREFIXES: tuple[str, ...] = (
    "pypa/gh-action-pypi-publish",       # PyPI trusted publishing (PEP 740)
    "google-github-actions/auth",        # GCP Workload Identity Federation
    "azure/login",                       # Azure OIDC login
    "hashicorp/vault-action",            # HashiCorp Vault JWT auth
    "sigstore/cosign-installer",         # cosign keyless signing (uses OIDC)
    "actions/attest-build-provenance",   # native build-provenance attestation
    "actions/attest",                    # generic attestation action
    "slsa-framework/slsa-",              # SLSA generators
    "slsa-github-generator",             # SLSA generators (alt path)
    "ossf/scorecard-action",             # publishes results to Scorecard API via OIDC
)


def _is_oidc_step(step: dict[str, Any]) -> bool:
    """True when the step is a known OIDC-consuming action.

    AWS' ``configure-aws-credentials`` is recognized when paired with a
    ``role-to-assume`` input (the OIDC mode flag);
    ``docker/build-push-action`` is recognized when paired with
    ``provenance:`` or ``sbom:`` (both signed via Sigstore using the
    workflow's id-token); other OIDC actions are matched on their
    action path alone since they always consume the id-token when
    invoked.
    """
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    with_block = step.get("with") or {}
    if "configure-aws-credentials" in uses and "role-to-assume" in with_block:
        return True
    if "docker/build-push-action" in uses:
        prov = with_block.get("provenance")
        sbom = with_block.get("sbom")
        if prov not in (None, False, "false") or sbom not in (None, False, "false"):
            return True
    return any(prefix in uses for prefix in _OIDC_ACTION_PREFIXES)


#: Per-write-scope ``uses:`` substring patterns. A step whose ``uses:``
#: contains any of these substrings is treated as a consumer of the
#: matching scope (the action's documented behavior writes through the
#: GITHUB_TOKEN at that scope).
_SCOPE_CONSUMERS_USES: dict[str, tuple[str, ...]] = {
    "contents": (
        "peter-evans/create-pull-request",
        "ad-m/github-push-action",
        "stefanzweifel/git-auto-commit-action",
        "googleapis/release-please-action",
        "release-drafter/release-drafter",
        "softprops/action-gh-release",
        "ncipollo/release-action",
        "EndBug/add-and-commit",
        "anothrNick/github-tag-action",
        "actions/create-release",
    ),
    "pull-requests": (
        "peter-evans/create-or-update-comment",
        "peter-evans/create-pull-request",
        "marocchino/sticky-pull-request-comment",
        "actions/labeler",
        "hmarr/auto-approve-action",
        "dependabot/fetch-metadata",
        "amannn/action-semantic-pull-request",
    ),
    "issues": (
        "actions-cool/issues-helper",
        "peter-evans/create-or-update-comment",
    ),
    "security-events": (
        "github/codeql-action",   # all subpaths (upload-sarif, analyze)
        "anchore/scan-action",
        "aquasecurity/trivy-action",
        "ossf/scorecard-action",  # publishes results + uploads SARIF
    ),
    "pages": (
        "actions/deploy-pages",
        "actions/upload-pages-artifact",
        "JamesIves/github-pages-deploy-action",
    ),
    "checks": (
        "dorny/test-reporter",
        "mikepenz/action-junit-report",
        "EnricoMi/publish-unit-test-result-action",
        "test-summary/action",
    ),
    "actions": (
        "benc-uk/workflow-dispatch",
        "convictional/trigger-workflow-and-wait",
    ),
}

#: Per-write-scope ``run:`` body regex patterns. A step whose ``run:``
#: matches the pattern is treated as a consumer of the matching scope.
#: Each pattern is anchored on word boundaries so substring text in a
#: comment doesn't trigger.
_SCOPE_CONSUMERS_RUN: dict[str, re.Pattern[str]] = {
    "contents": re.compile(
        r"\b(?:"
        r"git\s+push"
        r"|git\s+tag\b"
        r"|gh\s+release\s+(?:create|upload|edit|delete)"
        r")\b"
    ),
    "pull-requests": re.compile(
        r"\bgh\s+pr\s+(?:create|comment|edit|review|merge|"
        r"close|reopen|ready|lock|unlock)\b"
    ),
    "packages": re.compile(
        r"\b(?:"
        r"docker\s+push"
        r"|npm\s+publish"
        r"|gh\s+release\s+upload"
        r"|cargo\s+publish"
        r"|twine\s+upload"
        r")\b"
    ),
    "issues": re.compile(
        r"\bgh\s+issue\s+(?:create|comment|edit|close|reopen|"
        r"lock|unlock|delete|pin|unpin|transfer)\b"
    ),
    "security-events": re.compile(
        r"\bgh\s+api\s+\S*?code-scanning\b"
    ),
    "deployments": re.compile(
        r"\bgh\s+api\s+\S*?deployments\b"
    ),
    "statuses": re.compile(
        r"\bgh\s+api\s+\S*?statuses\b"
    ),
    "actions": re.compile(
        r"\bgh\s+(?:workflow|run)\s+(?:run|cancel|rerun|delete)\b"
    ),
}

#: Wildcard consumers. A step using one of these can mutate any scope
#: through the GitHub API, so the rule conservatively treats them as
#: consumers of every granted write scope.
_WILDCARD_CONSUMER_PREFIXES: tuple[str, ...] = (
    "actions/github-script",
)


def _step_is_wildcard_consumer(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    return any(prefix in uses for prefix in _WILDCARD_CONSUMER_PREFIXES)


def _step_consumes_scope(step: dict[str, Any], scope: str) -> bool:
    """True when *step* consumes the given write scope.

    Wildcard consumers (``actions/github-script``) match every scope.
    Otherwise the step's ``uses:`` is substring-matched against the
    per-scope ``_SCOPE_CONSUMERS_USES`` list, and the ``run:`` body is
    regex-matched against ``_SCOPE_CONSUMERS_RUN``. Special-case:
    ``docker/build-push-action`` with a truthy ``with.push:`` counts
    as a ``packages: write`` consumer (it performs ``docker push``
    internally).
    """
    if _step_is_wildcard_consumer(step):
        return True
    uses = step.get("uses")
    if isinstance(uses, str):
        for substring in _SCOPE_CONSUMERS_USES.get(scope, ()):
            if substring in uses:
                return True
        # docker/build-push-action special case for packages: write.
        if scope == "packages" and "docker/build-push-action" in uses:
            with_block = step.get("with") or {}
            push = with_block.get("push")
            if push not in (None, False, "false", "no", "off", "0"):
                return True
    run = step.get("run")
    if isinstance(run, str):
        pattern = _SCOPE_CONSUMERS_RUN.get(scope)
        if pattern is not None and pattern.search(run):
            return True
    return False


def _job_consumes_scope(job: dict[str, Any], scope: str) -> bool:
    """True when at least one step in *job* consumes *scope*."""
    for step in iter_steps(job):
        if _step_consumes_scope(step, scope):
            return True
    return False


#: Write scopes the overprovisioning check can analyze. Scopes outside
#: this set (``models``, ``attestations``, ``discussions``,
#: ``repository-projects``) stay silent until a consumer catalog
#: exists for them; that's conservative on purpose, the alternative is
#: false-firing on rarer scopes.
_SCOPES_WITH_CONSUMERS: frozenset[str] = frozenset(
    set(_SCOPE_CONSUMERS_USES.keys()) | set(_SCOPE_CONSUMERS_RUN.keys()),
)


def _excess_write_scopes(perms: Any, job: dict[str, Any]) -> list[str]:
    """Return write scopes the job grants but no step justifies.

    Skips reusable-workflow callers (``jobs.<id>.uses:``): the callee
    consumes the permissions, the caller's empty step list can't
    answer the question.

    Skips ``id-token``: the existing ``_perms_issues`` block already
    checks it with reusable-workflow-aware semantics; double-firing
    would emit redundant findings.
    """
    if not isinstance(perms, dict):
        return []
    if isinstance(job.get("uses"), str):
        return []
    excess: list[str] = []
    for scope, value in perms.items():
        if not isinstance(scope, str) or scope == "id-token":
            continue
        if value != "write":
            continue
        if scope not in _SCOPES_WITH_CONSUMERS:
            continue
        if _job_consumes_scope(job, scope):
            continue
        excess.append(scope)
    return excess


def _perms_issues(
    perms: Any, job_id: str, triggers: list[str],
    job: dict[str, Any] | None = None,
) -> list[str]:
    """Return human-readable issues with a permissions block."""
    issues: list[str] = []
    if _is_write_all(perms):
        issues.append(f"{job_id}: `permissions: write-all` is overly broad")
    if isinstance(perms, dict):
        # contents: write on a PR-triggered workflow is suspicious
        pr_triggers = {"pull_request", "pull_request_target"}
        if perms.get("contents") == "write" and pr_triggers & set(triggers):
            issues.append(
                f"{job_id}: `contents: write` on a pull_request workflow"
            )
        # id-token: write without a corresponding OIDC step. Skipped
        # for reusable-workflow callers (``jobs.<id>.uses:`` set, no
        # ``steps:``): the grant is forwarded to the called workflow,
        # which is the actual OIDC consumer. Inspecting the caller's
        # empty step list would always FP on legitimate slsa-github-
        # generator / attest-build-provenance reusable workflow calls.
        if (
            perms.get("id-token") == "write"
            and job is not None
            and not isinstance(job.get("uses"), str)
        ):
            has_oidc = any(
                _is_oidc_step(s) for s in iter_steps(job)
            )
            if not has_oidc:
                issues.append(
                    f"{job_id}: `id-token: write` with no OIDC step"
                )
        # Overprovisioned write scopes: any other write grant the job
        # doesn't consume. Only checked per-job (top-level grants
        # apply to every job that doesn't override, so attributing
        # excess to the workflow level requires aggregating across
        # jobs, a follow-up).
        if job is not None:
            for scope in _excess_write_scopes(perms, job):
                issues.append(
                    f"{job_id}: `{scope}: write` granted, "
                    f"no step consumes it"
                )
    return issues


def check(path: str, doc: dict[str, Any], wf: Workflow | None = None) -> Finding:
    triggers = workflow_triggers(doc)
    issues: list[str] = []

    # Check top-level permissions.
    top_perms = doc.get("permissions")
    # Resolved callees inherit their caller's permissions block when
    # they don't declare their own. Treat the inherited block as the
    # effective top-level for the absence-check below, otherwise
    # every legitimate reusable workflow gets flagged.
    inherited = wf.inherited_permissions if wf is not None else None
    effective_top = top_perms if top_perms is not None else inherited
    if top_perms is not None:
        issues.extend(_perms_issues(top_perms, "<workflow>", triggers))

    # Check per-job permissions.
    jobs_missing: list[str] = []
    for job_id, job in iter_jobs(doc):
        job_perms = job.get("permissions")
        if job_perms is not None:
            issues.extend(
                _perms_issues(job_perms, job_id, triggers, job=job)
            )
        elif effective_top is None:
            jobs_missing.append(job_id)

    # Track reusable-workflow callers whose permissions can't be
    # verified without resolving the callee.
    reusable_callers = [
        jid for jid, j in iter_jobs(doc)
        if isinstance(j.get("uses"), str)
    ]

    if jobs_missing:
        issues.append(
            f"{len(jobs_missing)} job(s) without permissions: "
            f"{', '.join(jobs_missing)}"
        )

    # Top-level write-scope aggregation: a write scope at workflow
    # level is excess when no job that inherits it consumes it.
    if isinstance(top_perms, dict):
        inheriting_jobs = [
            (jid, j) for jid, j in iter_jobs(doc)
            if j.get("permissions") is None
            and not isinstance(j.get("uses"), str)
        ]
        if inheriting_jobs:
            for scope, value in top_perms.items():
                if not isinstance(scope, str) or scope == "id-token":
                    continue
                if value != "write":
                    continue
                if scope not in _SCOPES_WITH_CONSUMERS:
                    continue
                consumed = any(
                    _job_consumes_scope(j, scope)
                    for _, j in inheriting_jobs
                )
                if not consumed:
                    issues.append(
                        f"<workflow>: top-level `{scope}: write` "
                        f"not consumed by any inheriting job"
                    )

    passed = not issues

    reusable_note = ""
    if reusable_callers:
        shown = ", ".join(reusable_callers[:3])
        overflow = (
            f" (+{len(reusable_callers) - 3} more)"
            if len(reusable_callers) > 3
            else ""
        )
        reusable_note = (
            f" {len(reusable_callers)} job(s) call reusable workflows "
            f"({shown}{overflow}) whose permissions could not be "
            f"verified without ``--resolve-remote``."
        )

    if passed:
        desc = (
            "Workflow declares a permissions block with no overly broad grants."
        )
        if reusable_note:
            desc += reusable_note
    else:
        desc = (
            f"Permissions issues detected: {'; '.join(issues)}. "
            f"The GITHUB_TOKEN may have more privilege than necessary."
        )
        if reusable_note:
            desc += reusable_note
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
