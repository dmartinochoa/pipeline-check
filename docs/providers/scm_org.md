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

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ORG-001](#org-001) | Organization does not require two-factor authentication | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-002](#org-002) | Organization default member permission grants write to every repo | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-003](#org-003) | Organization allows any GitHub Action to run (no allow-list) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-004](#org-004) | Organization default workflow token grants write permissions | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-005](#org-005) | Organization lets GitHub Actions approve pull requests | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-006](#org-006) | Organization Actions secret is exposed to every repository | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-007](#org-007) | Organization allows forking of private repositories | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ORG-008](#org-008) | Organization lets members create public repositories | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ORG-009](#org-009) | Organization self-hosted runner group is available to public repositories | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-010](#org-010) | New repositories default to secret scanning without push protection | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ORG-011](#org-011) | Organization webhook delivers events over insecure transport | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-012](#org-012) | New repositories get Dependabot alerts but not security updates | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [ORG-013](#org-013) | Organization ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

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

<div class="pg-rule pg-rule--medium" markdown>

## ORG-007: Organization allows forking of private repositories { #org-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Reads ``members_can_fork_private_repositories`` from ``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and fires when it is ``true``. ``false`` passes. The field is only returned to an org-owner-scoped token (``admin:org``); when absent the rule passes with an 'unavailable' note rather than guessing, so a low-scope token never produces a false finding. Individual repos can still restrict forking below this org default.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn off ``Allow forking of private repositories`` (Org Settings -> Member privileges -> Repository forking). When it is on, any member can fork a private or internal repository to their personal account, where the org's branch protection, audit log, secret scanning, and 2FA policy no longer apply, and the copy persists after the member leaves. That moves source code outside the controls that govern the org, a data-exfiltration and IP-leak path that needs no exploit. Allow forking only for the specific repos that require it, and prefer forking within the org.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ORG-008: Organization lets members create public repositories { #org-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Reads ``members_can_create_public_repositories`` from ``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 / ORG-007 use) and fires when it is ``true``. ``false`` passes. When repository creation is disabled for members altogether (``members_can_create_repositories: false``) the rule passes, since the public sub-setting is then moot. The field is only returned to an org-owner-scoped token (``admin:org``); when absent the rule passes with an 'unavailable' note rather than guessing, so a low-scope token never produces a false finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict public-repository creation to organization owners (Org Settings -> Member privileges -> Repository creation: allow members to create only ``Private`` repositories, or no repositories). When any member can create a ``Public`` repository, one push of internal code to a member-created public repo exposes source, secrets, or customer data to the whole internet, with no review and no admin in the loop. Owners can still create public repos for genuine open-source work, and members get private repos for everything else.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-009: Organization self-hosted runner group is available to public repositories { #org-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Reads ``GET /orgs/{org}/actions/runner-groups`` and fires when any group has ``allows_public_repositories: true``. Group names are listed so the operator can find them. The org-governance analog of GHA-105 (a self-hosted runner reachable from an untrusted PR trigger) and GLRUN-005 (a fork pipeline on a self-managed runner). Needs a token with the ``admin:org`` / ``manage_runners:org`` scope; when the endpoint is unavailable (no scope, or the org has no runner groups) the rule passes with a note.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn off ``Allow public repositories`` on the runner group (Org Settings -> Actions -> Runner groups -> edit the group). When it is on, a workflow in any public repository, including a pull request from a fork, can run jobs on the org's self-hosted runners. Fork code then executes on persistent infrastructure you operate: it can read other jobs' files, steal cached credentials, pivot into the network, or leave a backdoor on the host. GitHub's own hardening guidance is that self-hosted runners should never be available to public repositories. Use ephemeral, isolated runners for public repos, or keep the runner group scoped to trusted private repos.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ORG-010: New repositories default to secret scanning without push protection { #org-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``secret_scanning_enabled_for_new_repositories`` and ``secret_scanning_push_protection_enabled_for_new_repositories`` from ``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and fires only when scanning is on for new repos but push protection is not, the org-default half-adoption. When scanning itself is off for new repos the rule passes (the push-protection default is then moot, and the field is plan-dependent), so an org without GitHub Advanced Security never produces a false finding. When the fields are absent (low scope / no security features) the rule passes with a note. The org-default analog of SCM-015 (per-repo push protection off).

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Automatically enable for new repositories`` for secret scanning push protection (Org Settings -> Code security -> Secret protection / Push protection). The organization already enables secret scanning by default for new repos (the detect step), but without push protection (the prevent step) every new repo starts out catching credentials only after they land in git history, where rotation is the only fix. Enabling the push-protection default refuses the push before the secret is ever committed. The per-repo analog is SCM-015.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ORG-011: Organization webhook delivers events over insecure transport { #org-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Reads ``GET /orgs/{org}/hooks`` and fires on any active webhook whose ``config.url`` starts with ``http://`` or whose ``config.insecure_ssl`` is ``"1"`` (TLS verification off). Inactive hooks (``active: false``) are skipped. Scoped to transport security: unlike the per-repo SCM-026 it does not flag a missing HMAC secret, because the org hooks endpoint does not reliably report secret presence. Needs a token with the ``admin:org_hook`` / ``admin:org`` scope; when the endpoint is unavailable the rule passes with a note. The org-level analog of SCM-026.

<div class="pg-rule__rec" markdown>

**Recommended action**

For each flagged organization webhook (Org Settings -> Webhooks -> edit), switch the Payload URL to ``https://`` and set SSL verification to ``Enable SSL verification``. An org-level webhook fires on events across every repository, so its payloads carry pull request diffs, push commits, and security-alert content for the whole org. Over plain HTTP (or HTTPS with verification disabled) a network attacker between GitHub and the receiver reads all of it, and can tamper with deliveries. Also set a strong ``Secret`` and validate the ``X-Hub-Signature-256`` header on the receiver.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ORG-012: New repositories get Dependabot alerts but not security updates { #org-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Reads ``dependabot_alerts_enabled_for_new_repositories`` and ``dependabot_security_updates_enabled_for_new_repositories`` from ``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and fires only when alerts are on for new repos but security updates are not, the org-default half-adoption. When Dependabot alerts are off for new repos the rule passes (security updates require alerts first, and the field is plan-dependent), so an org without Dependabot never produces a false finding. When the fields are absent (low scope) the rule passes with a note. The org-default analog of SCM-005.

<div class="pg-rule__rec" markdown>

**Recommended action**

Turn on ``Automatically enable for new repositories`` for Dependabot security updates (Org Settings -> Code security -> Dependabot security updates). The organization already turns on Dependabot alerts by default for new repos (so a vulnerable dependency is surfaced), but without security updates every new repo only gets the alert, with no automatic pull request that bumps the dependency to a fixed version. Teams then patch by hand, slowly or not at all. Enabling the security-updates default closes the loop from 'a vulnerable dependency was detected' to 'a fix PR is waiting'. The per-repo analog is SCM-005.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ORG-013: Organization ruleset is in evaluate / disabled mode (not enforced) { #org-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-693</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Walks ``GET /orgs/{org}/rulesets`` and flags every entry whose ``enforcement`` is anything other than ``"active"`` (``evaluate`` = dry-run, ``disabled`` = explicit off). Passes when no org rulesets are configured (``[]``). Needs a token with the ``admin:org`` scope; when the endpoint is unavailable the rule passes with a note. The org-level analog of SCM-029.

**Known false-positive modes**

- A freshly-authored org ruleset legitimately sits in ``evaluate`` mode for a short audit window before promotion to ``active``. Suppress for that specific ruleset id with a calendar-bound rationale; the rule keeps flagging until the promotion lands so the transition window doesn't quietly become permanent.

<div class="pg-rule__rec" markdown>

**Recommended action**

Flip every non-enforcing organization ruleset to ``enforcement: active`` (Org Settings -> Repository -> Rulesets -> <name> -> Enforcement status -> Active). An org-level ruleset applies branch / tag / push governance across every repository the ruleset targets, so a single ruleset left in ``evaluate`` (preview, runs the rule logic but never blocks) or ``disabled`` (explicit off) leaves all of those repos with the audit appearance of org-wide governance and the behavior of none. Operators commonly create a ruleset in ``evaluate`` to preview its effect and forget to promote it.

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
