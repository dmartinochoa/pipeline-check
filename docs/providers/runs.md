# GitHub Actions run forensics

Where the `github` provider reasons about what a workflow *could* do,
the `runs` provider audits what *actually executed*. It pulls recent
Actions runs via the REST API
(`GET /repos/{owner}/{repo}/actions/runs`) and flags runs that fired on
a privileged trigger (`pull_request_target` / `workflow_run`) and, in
particular, any whose head came from a fork: untrusted code that ran
with the base repository's secrets and a write-scoped `GITHUB_TOKEN`.
That is the live shape of the tj-actions/changed-files (CVE-2025-30066)
and GhostAction incidents, which were visible in run history before
anyone read the workflow file.

Findings carry the run's URL, actor, and trigger so an operator can
open the run directly. A missing token, a 404, or a network error
degrades to a warning (every rule then sees an empty run list and
passes) rather than crashing the scan.

## Producer workflow

```bash
# Token comes from --gh-token or $GITHUB_TOKEN (needs ``actions:read``).
pipeline_check --pipeline runs --scm-repo owner/name \
               --gh-token "$GITHUB_TOKEN"
```

## What it covers

4 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [RUN-001](#run-001) | Fork PR executed on a privileged trigger | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [RUN-002](#run-002) | Privileged trigger exercised in run history | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [RUN-003](#run-003) | Secret leaked in workflow run logs | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [RUN-004](#run-004) | Fork PR run minted a cloud OIDC token | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## RUN-001: Fork PR executed on a privileged trigger { #run-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Sourced from the GitHub Actions REST API (``GET /repos/{owner}/{repo}/actions/runs``). A run is flagged when its ``event`` is a privileged trigger (``pull_request_target`` / ``workflow_run``) and its ``head_repository`` is a fork (or differs from the base repository). Unlike the static GHA-002 check this is evidence the dangerous path actually ran, so it survives even when the workflow file has since been deleted or rewritten.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat each flagged run as untrusted-code execution in a privileged context. Confirm the workflow that ran does not check out and execute the PR head, and move any build-from-PR logic into a separate unprivileged ``pull_request`` workflow (the label-then-build pattern). Rotate any secret the run could read if the workflow is not demonstrably safe.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## RUN-002: Privileged trigger exercised in run history { #run-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Sourced from the Actions REST API. Counts recent runs whose ``event`` is ``pull_request_target`` or ``workflow_run``. This is forensic context (the surface is live in production), which the static config scan cannot confirm on its own.

<div class="pg-rule__rec" markdown>

**Recommended action**

Review the workflows that run on these triggers and confirm none check out or execute PR-controlled content while holding secrets. See RUN-001 for any of these runs that came from a fork (the high-severity subset).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## RUN-003: Secret leaked in workflow run logs { #run-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Only evaluated with ``--audit-runs-logs``. Downloads each privileged-trigger run's log archive (the Actions REST API ``.../logs`` endpoint) and scans the text with the shared secret-shape catalog (``find_secret_values``). GitHub masks registered secrets, so a match is a credential that leaked past masking. The token value is redacted in the finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the leaked credential immediately, then stop it reaching the log: register it as an Actions secret so GitHub masks it, avoid `set -x` / `env` dumps in steps that hold it, and pipe tool output that may echo credentials through a redactor.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## RUN-004: Fork PR run minted a cloud OIDC token { #run-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Only evaluated with ``--audit-runs-logs``. Reuses the privileged-trigger run logs RUN-003 downloads (the Actions REST API ``.../logs`` endpoint) and flags a run whose logs show OIDC token minting (``token.actions.githubusercontent.com``, the ``ACTIONS_ID_TOKEN_REQUEST_*`` env, AWS ``AssumeRoleWithWebIdentity``, or GCP ``workloadIdentityPools``). Scoped to fork-originated runs, so a trusted-branch deploy that uses OIDC normally does not fire. Detection is high-precision but best-effort on recall (log content varies; registered secrets are masked).

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat this as untrusted code that reached cloud federation: rotate / review the federated role's recent activity and assume the run could act as that role. Restrict the role's trust policy so a fork / PR ref cannot assume it (pin the subject to your protected branches and environments), and move any OIDC-authenticated step out of the privileged ``pull_request_target`` / ``workflow_run`` path that handles PR content (the label-then-deploy pattern).

</div>

</div>

---

## Adding a new GitHub Actions run forensics check

1. Create a new module at
   `pipeline_check/core/checks/runs/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/runs/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py runs
   ```
