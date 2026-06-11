# GitLab pipeline run forensics

Where the `gitlab` provider reasons about what a `.gitlab-ci.yml` *could*
do, the `gitlab_runs` provider audits what *actually executed*. It pulls
recent pipelines via the GitLab REST API
(`GET /projects/:id/pipelines`) and flags pipelines that ran on a
merge-request event: code a contributor proposed, and (when "Run
pipelines for fork merge requests" is enabled) code from a fork running
in the project's CI context. This is the GitLab analog of the `runs`
provider's GitHub Actions forensics.

Findings carry the pipeline's URL and trigger source so an operator can
open the pipeline directly. A missing token, a 404, or a network error
degrades to a warning (every rule then sees an empty pipeline list and
passes) rather than crashing the scan.

## Producer workflow

```bash
# Token comes from --gitlab-token or $GITLAB_TOKEN (needs ``read_api``).
pipeline_check --pipeline gitlab_runs --scm-repo group/project \
               --gitlab-token "$GITLAB_TOKEN"
```

## What it covers

5 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GLRUN-001](#glrun-001) | Merge-request pipeline exercised in run history | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GLRUN-002](#glrun-002) | Fork merge-request pipeline executed in run history | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GLRUN-003](#glrun-003) | Secret leaked in a fork pipeline's job trace | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GLRUN-004](#glrun-004) | Fork pipeline minted a cloud OIDC token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GLRUN-005](#glrun-005) | Fork pipeline ran on a self-managed runner | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## GLRUN-001: Merge-request pipeline exercised in run history { #glrun-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Sourced from the GitLab REST API (``GET /projects/:id/pipelines``). Counts recent pipelines whose ``source`` is ``merge_request_event`` or ``external_pull_request_event``. This is forensic context (the merge-request pipeline surface is live in production), which the static ``.gitlab-ci.yml`` scan cannot confirm on its own. The fork-originated subset (the high-severity case) is a separate, deeper check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Review the jobs that run on merge-request pipelines and confirm none execute contributor-controlled content while holding CI/CD variables or a deploy token. If 'Run pipelines for fork merge requests' is enabled, treat those pipelines as running untrusted code: scope protected variables and runners away from them, and require a maintainer to approve fork-MR pipelines before they run.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GLRUN-002: Fork merge-request pipeline executed in run history { #glrun-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Only evaluated with ``--audit-runs-logs``. Resolves fork-origin via the GitLab MR API: lists recent merge requests, keeps those whose ``source_project_id`` differs from the ``target_project_id`` (a fork), and pulls each such MR's pipelines (``/merge_requests/:iid/pipelines``). Each fork pipeline ran untrusted code in this project's CI. Independent of GLRUN-001's metadata pass; the fork-MR fetch is bounded to the most recent fork merge requests.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat fork merge-request pipelines as running untrusted code. Require a project member to approve fork-MR pipelines before they run (the 'Pipelines must be approved' setting), keep protected CI/CD variables and protected runners away from them, and run fork-MR jobs on isolated, ephemeral runners with no standing cloud credentials. If fork-MR pipelines are not needed, disable 'Run pipelines for fork merge requests'.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GLRUN-003: Secret leaked in a fork pipeline's job trace { #glrun-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Only evaluated with ``--audit-runs-logs``. Downloads each resolved fork pipeline's job traces (the GitLab REST API ``GET /projects/:id/jobs/:job_id/trace``) and scans the text with the shared secret-shape catalog (``find_secret_values``). GitLab masks marked variables, so a match is a credential that leaked past masking. Scoped to the fork pipelines GLRUN-002 resolves (the untrusted-code surface); the token value is redacted in the finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the leaked credential immediately, then stop it reaching the trace: mark it a masked (and protected) CI/CD variable so GitLab redacts it, avoid ``set -x`` / ``env`` dumps in jobs that hold it, and pipe tool output that may echo credentials through a redactor. Keep protected variables away from fork merge-request pipelines entirely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GLRUN-004: Fork pipeline minted a cloud OIDC token { #glrun-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Only evaluated with ``--audit-runs-logs``. Reuses the fork-pipeline job traces GLRUN-003 downloads and flags a fork pipeline whose trace shows cloud OIDC federation (AWS ``AssumeRoleWithWebIdentity`` or GCP ``workloadIdentityPools``). Scoped to fork pipelines, so a trusted-branch pipeline that uses OIDC normally does not fire. Detection is high-precision but best-effort on recall (trace content varies; masked variables are redacted).

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat this as untrusted code that reached cloud federation: rotate / review the federated role's recent activity and assume the pipeline could act as that role. Restrict the cloud trust policy so a fork / merge-request ref cannot assume it (bind the subject to your protected branches and the project's own ID-token audience), and keep ``id_tokens:`` jobs out of fork merge-request pipelines.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GLRUN-005: Fork pipeline ran on a self-managed runner { #glrun-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span>
</div>

Only evaluated with ``--audit-runs-logs``. Reads the ``runner`` embedded in each fork-pipeline job (the same ``/jobs`` page GLRUN-003 / GLRUN-004 list) and flags a fork pipeline whose jobs ran on a self-managed runner (``is_shared: false``, i.e. a ``project_type`` / ``group_type`` runner the owner operates). GitLab.com ``instance_type`` shared runners are ephemeral and not flagged. Independent of secrets / OIDC, so it catches a plain fork MR pipeline that merely executed on your own infrastructure. The fork-pipeline fetch is bounded to the most recent pipelines.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not run fork merge-request code on self-managed runners. In the project / group CI settings, disable shared-and-specific runners for fork MR pipelines, or require maintainer approval before a pipeline runs for a fork merge request, and run fork-triggered pipelines on ephemeral shared runners instead. If self-managed runners are required, isolate them (single-use VMs, a locked-down network, no standing cloud credentials) and tag them so only trusted pipelines target them.

</div>

</div>

---

## Adding a new GitLab pipeline run forensics check

1. Create a new module at
   `pipeline_check/core/checks/gitlab_runs/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/gitlab_runs/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py gitlab_runs
   ```
