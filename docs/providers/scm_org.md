# SCM org governance: GitHub

Where the [`scm`](scm_github.md) provider audits one repository's
settings, the `scm_org` provider audits the organization-wide controls
that govern every repository at once: whether two-factor authentication
is required of all members, the default permission members get on org
repos, and the rest of the org-admin settings layer. It pulls
`GET /orgs/{org}` (and sibling endpoints as the rule pack grows) via the
same GitHub REST fetcher the `scm` provider uses.

The org-admin settings are only returned to a token with `admin:org` /
`read:org` scope; without one, or on any 404 / network error, each rule
passes with an "unavailable" note rather than firing on absence, so a
low-scope token never produces a false finding.

## Producer workflow

```bash
# Token comes from --gh-token or $GITHUB_TOKEN (needs admin:org / read:org).
pipeline_check --pipeline scm_org --scm-org my-org --gh-token "$GITHUB_TOKEN"
```

## What it covers

6 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ORG-001](#org-001) | Organization does not require two-factor authentication | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-002](#org-002) | Organization default member permission grants write to every repo | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-003](#org-003) | Organization allows any GitHub Action to run (no allow-list) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-004](#org-004) | Organization default workflow token grants write permissions | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-005](#org-005) | Organization lets GitHub Actions approve pull requests | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-006](#org-006) | Organization Actions secret is exposed to every repository | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ORG-001: Organization does not require two-factor authentication { #org-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-308</span>
</div>

Reads ``two_factor_requirement_enabled`` from ``GET /orgs/{org}``. Fires when it is ``false``. The field is only returned to a token with org-owner scope (``admin:org`` / ``read:org``); when it is absent the rule passes with an 'unavailable' note rather than guessing, so a low-scope token never produces a false finding. Org-wide 2FA is the single highest-leverage account-takeover control and the flagship check of org-posture scanners (Legitify / Allstar).

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Require two-factor authentication for everyone in the organization`` (Org Settings -> Authentication security). Without it, a single phished or reused member password is enough to push to repositories, approve pull requests, or mint tokens as that member. Note that enabling the requirement removes members and outside collaborators who don't have 2FA configured, so audit the member list first.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-002: Organization default member permission grants write to every repo { #org-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``default_repository_permission`` from ``GET /orgs/{org}`` and fires when it is ``write`` or ``admin``. ``read`` / ``none`` pass. The field is only returned to an org-owner-scoped token (``admin:org``); when absent the rule passes with an 'unavailable' note rather than guessing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the organization's ``Base permissions`` (Org Settings -> Member privileges) to ``Read`` or ``No permission`` and grant write/admin per-repository through teams. A ``Write`` or ``Admin`` base permission means every member can push to (or reconfigure) every repository in the org, so one compromised member account can tamper with any project's code. Least privilege scopes write access to the repos a member actually works on.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-003: Organization allows any GitHub Action to run (no allow-list) { #org-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``allowed_actions`` from ``GET /orgs/{org}/actions/permissions`` and fires when it is ``all``. ``selected`` (curated allow-list) and ``local_only`` (only actions defined in the same repo) pass. The endpoint needs a token with the ``actions`` (or org-admin) scope; when unavailable the rule passes with a note rather than guessing. An org that has disabled Actions entirely (``enabled_repositories: none``) also passes, since no third-party action can run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict which actions can run org-wide (Org Settings -> Actions -> Policies). Set ``allowed_actions`` to ``selected`` and curate the allow-list (GitHub-authored plus a vetted set of verified creators / specific actions), or at minimum ``local_only``. Leaving it at ``all`` lets every workflow in every repo pull in any third-party action by a mutable tag, so one compromised or typosquatted action (the tj-actions / reviewdog class) executes across the whole org with each consuming workflow's token.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-004: Organization default workflow token grants write permissions { #org-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Reads ``default_workflow_permissions`` from ``GET /orgs/{org}/actions/permissions/workflow`` and fires when it is ``write``. ``read`` passes. The endpoint needs a token with the ``actions`` / org-admin scope; when unavailable the rule passes with a note. This is the org-wide default; individual workflows can still scope the token down (or up) with a ``permissions:`` block, which the per-workflow GHA rules evaluate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the organization's default ``GITHUB_TOKEN`` permissions to read-only (Org Settings -> Actions -> Workflow permissions -> ``Read repository contents and packages permissions``). A ``write`` default hands every workflow in every repo a token that can push code, publish packages, and edit releases unless a workflow narrows it with a ``permissions:`` block, so a script injection or a compromised action escalates straight to repo write. Grant write back per-workflow / per-job where it's needed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-005: Organization lets GitHub Actions approve pull requests { #org-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Reads ``can_approve_pull_request_reviews`` from ``GET /orgs/{org}/actions/permissions/workflow`` (the same fetch ORG-004 uses) and fires when it is ``true``. The endpoint needs a token with the ``actions`` / org-admin scope; when unavailable the rule passes with a note. Individual repos can still override this org default.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn off ``Allow GitHub Actions to create and approve pull requests`` (Org Settings -> Actions -> General -> Workflow permissions). When it is on, a workflow running with the ``GITHUB_TOKEN`` can submit an approving review, which can satisfy a required-review branch-protection rule without a human ever looking at the change. A merge-bot or an attacker who can trigger a workflow then self-approves a malicious PR. Require approvals from human reviewers (or a separate identity) instead.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-006: Organization Actions secret is exposed to every repository { #org-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads ``GET /orgs/{org}/actions/secrets`` and fires when any secret has ``visibility: all``. ``selected`` and ``private`` pass. The endpoint returns secret names and visibility only, never values; names are listed so the operator can find them. Needs a token with the ``admin:org`` (or secrets) scope; when unavailable the rule passes with a note. The repo-level analog is SCM-048 (org codespace secret scoped to all repos).

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope each org-level Actions secret to selected repositories (Org Settings -> Secrets and variables -> Actions -> edit the secret -> ``Repository access: Selected repositories``) instead of ``All repositories``. An all-repos secret is readable by every workflow in every current and future repo, including low-trust ones, so one script injection or compromised action in any repo exfiltrates it. Grant the secret only to the repos that build the system that needs it.

</div>

</div>

---

## Adding a new SCM org governance (GitHub) check

1. Create a new module at
   `pipeline_check/core/checks/scm_org/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/scm_org/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py scm_org
   ```
