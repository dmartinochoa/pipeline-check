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

1 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GLRUN-001](#glrun-001) | Merge-request pipeline exercised in run history | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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
