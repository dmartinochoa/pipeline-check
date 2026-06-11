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

2 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ORG-001](#org-001) | Organization does not require two-factor authentication | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ORG-002](#org-002) | Organization default member permission grants write to every repo | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
