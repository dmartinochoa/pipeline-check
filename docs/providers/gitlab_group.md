# GitLab group governance

Where the [`gitlab`](gitlab.md) provider audits one project's
`.gitlab-ci.yml`, the `gitlab_group` provider audits the group-wide
controls that govern every project in a GitLab group at once: whether
two-factor authentication is required of all members, whether members can
fork the group's projects outside the group, and the rest of the
group-owner settings layer. It pulls `GET /groups/{group}` via the same
GitLab REST v4 fetcher the `scm` provider's GitLab path uses. The GitLab
analog of the GitHub-only [`scm_org`](scm_org.md) provider.

The group-owner settings are only returned to a token with `read_api`
and Owner access to the group; without one, or on any 404 / network
error, each rule passes with an "unavailable" note rather than firing on
absence, so a low-scope token never produces a false finding.

## Producer workflow

```bash
# Token comes from --gitlab-token or $GITLAB_TOKEN (needs read_api + Owner).
pipeline_check --pipeline gitlab_group --scm-org my-group \
               --gitlab-token "$GITLAB_TOKEN"
```

## What it covers

4 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GLGRP-001](#glgrp-001) | GitLab group does not require two-factor authentication | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GLGRP-002](#glgrp-002) | GitLab group allows forking projects outside the group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GLGRP-003](#glgrp-003) | GitLab group allows sharing projects outside the group hierarchy | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GLGRP-004](#glgrp-004) | GitLab group default branch protection is disabled for new projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GLGRP-001: GitLab group does not require two-factor authentication { #glgrp-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-308</span>
</div>

Reads ``require_two_factor_authentication`` from ``GET /groups/{group}``. Fires when it is ``false``. The field is only returned to a token with Owner access to the group (``read_api``); when it is absent the rule passes with an 'unavailable' note rather than guessing, so a low-scope token never produces a false finding. Group-wide 2FA is the single highest-leverage account-takeover control.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Require all users in this group to set up two-factor authentication`` (Group Settings -> General -> Permissions and group features). Without it, a single phished or reused member password is enough to push to the group's projects, approve merge requests, or run pipelines as that member. Enabling the requirement starts a grace period after which members without 2FA lose access, so set ``two_factor_grace_period`` and notify the group first. The GitHub-org analog is ORG-001.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GLGRP-002: GitLab group allows forking projects outside the group { #glgrp-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Reads ``prevent_forking_outside_group`` from ``GET /groups/{group}`` and fires when it is ``false``. ``true`` passes. The field is a Premium / Ultimate group setting; on a plan or token that does not return it the rule passes with an 'unavailable' note rather than guessing, so a low-scope token or free-tier group never produces a false finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Prevent project forking outside current group`` (Group Settings -> General -> Permissions and group features). When it is off, any member can fork a private or internal project to a namespace outside the group, where the group's branch protection, approval rules, and member 2FA policy no longer apply, and the copy persists after the member leaves. That moves source code outside the controls that govern the group, a data-exfiltration and IP-leak path that needs no exploit. The GitHub-org analog is ORG-007.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GLGRP-003: GitLab group allows sharing projects outside the group hierarchy { #glgrp-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Reads ``prevent_sharing_groups_outside_hierarchy`` from ``GET /groups/{group}`` and fires when it is ``false`` (sharing outside the hierarchy is allowed). ``true`` passes. The setting is tied to Premium / SAML group features; on a plan or token that does not return it the rule passes with an 'unavailable' note rather than guessing, so a low-scope token or free-tier group never produces a false finding. Sits alongside GLGRP-002 (forking outside the group): both are group-level access-boundary controls.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Prevent members from sharing projects in this group with groups outside the hierarchy`` (Group Settings -> General -> Permissions and group features). When it is off, a member can share a private or internal project with a group outside the current hierarchy, granting that external group's members standing access to the project, outside the controls (branch protection, approval rules, 2FA policy, audit log) that govern this group. Restrict sharing to the hierarchy and grant external access only through reviewed, time-bound membership. The GitHub-org analog is ORG-007 (forking) / outside-collaborator policy.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GLGRP-004: GitLab group default branch protection is disabled for new projects { #glgrp-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Reads ``default_branch_protection`` from ``GET /groups/{group}`` and fires when it is ``0`` (Not protected). ``1``-``4`` (partial / full / protected-against-push / full-after-initial-push) pass. GitLab is migrating this integer to a ``default_branch_protection_defaults`` object; when only that newer form is returned (the integer absent) the rule passes with an 'unavailable' note rather than guessing at the object's shape, so it never produces a false finding. This is the group-wide default for new projects; SCM-001 audits a specific repository's branch protection.

<div class="pg-rule__rec" markdown>

**Recommended action**

Raise the group's ``Default branch protection`` above ``Not protected`` (Group Settings -> General -> Permissions and group features). At ``0`` (Not protected), every new project created in the group starts with a default branch any Developer can push to directly, force-push, and delete, with no review gate, so a single compromised or careless member can rewrite history or ship unreviewed code on day one. Set it to at least ``Partially protected`` (no force-push) and prefer ``Fully protected`` so new projects inherit a safe default; individual projects can still tighten it further. The repo-level analog is SCM-001.

</div>

</div>

---

## Adding a new GitLab group governance check

1. Create a new module at
   `pipeline_check/core/checks/gitlab_group/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/gitlab_group/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py gitlab_group
   ```
