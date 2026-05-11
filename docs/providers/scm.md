# SCM (source control management) posture provider

Scans repository governance via the platform's REST API: branch
protection, required reviews, code scanning, secret scanning,
Dependabot, signed commits, and the rest of the controls that
live at the repo / org settings layer rather than in workflow YAML.
Maps each rule to the OpenSSF Scorecard check it evidences and to
the CIS Software Supply Chain Security Guide section it satisfies.

Three platforms today: **GitHub** (full 19-rule pack), **GitLab**
and **Bitbucket Cloud** (universal subset of seven rules:
``SCM-001``, ``SCM-002``, ``SCM-006``, ``SCM-007``, ``SCM-008``,
``SCM-009``, ``SCM-017``). GitHub-only rules pass silently on the
other platforms with a "not applicable on PLATFORM" note so the
operator sees the deliberate skip rather than a silent absence.

Closes the gap between this scanner and Legitify / OpenSSF
Scorecard, neither of which scan pipeline-config files. Together
with the GitHub Actions provider, the posture coverage spans both
the repo settings and the workflows the repo runs.

## Producer workflow

```bash
# GitHub. Token comes from --gh-token or $GITHUB_TOKEN. Without
# admin scope on the repo, security_and_analysis features
# (SCM-004 / SCM-005 / SCM-015 / SCM-016) cannot distinguish
# "really disabled" from "I lacked visibility" — re-run with
# admin scope to confirm those rules' verdicts.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world

# GitLab. Token comes from --gh-token (the flag is shared across
# platforms) or $GITLAB_TOKEN; needs the ``read_api`` scope. Repo
# spec is the full project path (nested subgroups allowed).
pipeline_check --pipeline scm --scm-platform gitlab \
    --scm-repo group/subgroup/project

# Bitbucket Cloud. Token is ``user:app_password`` or the existing
# ``Basic <b64>`` Authorization value; falls back to
# $BITBUCKET_TOKEN. Repo spec is ``workspace/repo_slug``.
pipeline_check --pipeline scm --scm-platform bitbucket \
    --scm-repo acme/widget

# Offline / CI mode: read JSON responses from disk instead of
# hitting the network. Each endpoint maps to
# <endpoint-with-slashes-as-underscores>.json under DIR. Works on
# every platform.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world \
    --scm-fixture-dir ./scm-fixtures/
```

### Per-platform rule coverage

| Rule | GitHub | GitLab | Bitbucket | Notes |
|------|--------|--------|-----------|-------|
| SCM-001 (branch protection presence) | yes | yes | yes | Universal |
| SCM-002 (required reviews) | yes | yes | yes | GitLab: ``approvals_before_merge``; Bitbucket: ``require_approvals_to_merge`` |
| SCM-003 (default code scanning) | yes | skip | skip | GitHub-only |
| SCM-004 (secret scanning) | yes | skip | skip | GitHub-only |
| SCM-005 (Dependabot updates) | yes | skip | skip | GitHub-only |
| SCM-006 (signed commits required) | yes | yes | yes | GitLab: ``push_rules.reject_unsigned_commits``; Bitbucket: no enforcement, always fires |
| SCM-007 (force push allowed) | yes | yes | yes | Universal |
| SCM-008 (required status checks) | yes | yes | yes | GitLab: pipeline-must-succeed; Bitbucket: ``require_passing_builds_to_merge`` |
| SCM-009 (branch deletion allowed) | yes | yes | yes | GitLab protected branches block deletion implicitly; Bitbucket ``delete`` restriction |
| SCM-010..SCM-016 | yes | skip | skip | GitHub-only protection knobs / security features |
| SCM-017 (CODEOWNERS file present) | yes | yes | yes | GitLab also probes ``.gitlab/CODEOWNERS``; Bitbucket probes ``.bitbucket/CODEOWNERS`` |
| SCM-018, SCM-019 | yes | skip | skip | GitHub-only protection-payload shape |

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### What the rules expect

The provider hits three endpoints per repo:

  * ``GET /repos/{owner}/{repo}`` — repo metadata, default
    branch name, ``security_and_analysis`` feature states.
  * ``GET /repos/{owner}/{repo}/branches/{default}/protection`` —
    branch protection rule (404 = no rule).
  * ``GET /repos/{owner}/{repo}/code-scanning/default-setup`` —
    default code scanning state.

Three production cases produce ``security_and_analysis``-omitted
responses (which the rules treat as "not enabled" but flag in the
description):

  * The token lacks ``admin`` scope on the repo.
  * The repo is on a plan that doesn't expose the feature
    (e.g. private-repo Dependabot on a free org).
  * The repo metadata fetch itself failed.

Three FP-prevention guards keep noise out of the report:

  * **Empty repos** (``repo_meta.size == 0`` and no protection
    rule). SCM-001 passes with an "Empty repo" note rather than
    fail "no protection rule" on a brand-new repo with no commits.
  * **Archived / disabled repos**. GitHub auto-disables
    Dependabot, secret scanning, push protection, code scanning,
    and private vulnerability reporting on archived repos.
    SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016 detect the
    archive flag and pass with a "Skipped: archived repo" note.
    Branch-protection rules deliberately still evaluate — the
    audit-trail signal stays meaningful even when the repo is
    read-only.
  * **Repo-metadata-unavailable**. When the
    ``repos/{owner}/{repo}`` fetch fails, the provider does NOT
    probe ``branches/main/protection`` (which would FP for any
    repo whose default branch is not literally ``main``).
    SCM-001 surfaces a "Repo metadata unavailable" finding so
    the gap is visible rather than silent.

### SCM-specific checks

- **SCM-001 / SCM-007 / SCM-009**, branch protection presence,
  force-push denial, and deletion denial. Together they cover
  the rewrite-history attack class — without them, every other
  branch-protection knob the team configured can be erased
  after the fact.
- **SCM-002 / SCM-011 / SCM-012 / SCM-013 / SCM-014**, the review
  side of branch protection. Required count, CODEOWNERS
  routing, stale-review dismissal on force-push, conversation
  resolution, last-push approval. SCM-014 is the one that blocks
  the two-account collab review bypass.
- **SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016**, the
  ``security_and_analysis``-driven feature checks: code
  scanning, secret scanning, Dependabot security updates, secret-
  scanning push protection, private vulnerability reporting.
  All five share the archived-repo skip behavior.
- **SCM-006**, signed-commit enforcement on the default branch.
  Pairs with GHA-006 in the **XPC-005** chain to flag end-to-end
  provenance gaps (source unsigned + artifact unsigned = no
  cryptographic chain of custody).
- **SCM-010**, the meta-rule: branch protection enforces against
  administrators. Without it, every other protection knob is
  advisory rather than enforced.

### Cross-provider chains

When ``--pipelines github,scm`` (or ``--pipelines dockerfile,scm``)
is used together, five attack-chain rules in the ``XPC-NNN`` family
compose SCM findings with workflow / Dockerfile findings:

- **XPC-004**, ``SCM-001 ∨ SCM-007`` + ``GHA-019`` → token
  persistence on an unprotected default branch. CRITICAL composite
  because the attacker primitive collapses from "compromise the
  build runtime" to "open a PR, fetch the next build's
  artifacts."
- **XPC-005**, ``SCM-006`` + ``GHA-006`` → end-to-end provenance
  gap. Source unsigned and artifact unsigned together mean
  consumers can't verify what built from what, anywhere along
  the pipeline.
- **XPC-006**, ``SCM-002`` + ``GHA-002`` → unreviewed fork-PR
  privilege escalation. The pwn-request primitive (workflow uses
  ``pull_request_target`` and checks out PR head) plus a
  protection rule with no required reviews means a single
  insider can introduce or maintain the vulnerability without
  any human-review gate. CRITICAL composite.
- **XPC-007**, ``SCM-005`` + ``GHA-001`` → unpinned actions with
  no automated remediation. Tag-pinned ``uses:`` references plus
  Dependabot disabled means an upstream maintainer compromise
  propagates immediately to every workflow run AND there's no
  automated PR to move the team off the malicious version when
  the public CVE drops. The tj-actions/changed-files
  CVE-2025-30066 incident is the canonical instance.
- **XPC-008**, ``SCM-001 ∨ SCM-007`` + ``DF-001`` → unreviewed
  source ships a mutable runtime image. Insider-introducible
  Dockerfile change AND floating-tag base image: the team has
  two unrelated trust boundaries open at once and no compensating
  control to break the chain at.

## What it covers

19 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [SCM-001](#scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-002](#scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-003](#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-004](#scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-005](#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-006](#scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-007](#scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-008](#scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-009](#scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-010](#scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-011](#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-012](#scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-013](#scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-014](#scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-015](#scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-016](#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-017](#scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-018](#scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-019](#scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## SCM-001: Default branch has no protection rule { #scm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without a branch protection rule on the default branch, anyone with write access can force-push, delete the branch, or merge directly without review. Even when CI runs on the branch, an unprotected default branch lets a single compromised maintainer rewrite history and erase the audit trail. The check is sourced from the GitHub REST API (``GET /repos/{owner}/{repo}/branches/{branch}/protection``); a 404 response is itself the failure signal.

**Seen in the wild**

- Numerous post-incident reports (PyPI / RubyGems package compromises 2018-2024) trace the initial maintainer-account takeover step to the absence of branch protection: the attacker pushed a single tampered commit to the default branch, the release pipeline ran on push, the malicious build shipped to the registry within minutes, and recovery required force-pushing the audit trail itself. Branch protection turns the entire class of attack into a review-then-merge gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a branch protection rule on the default branch in the repository's Settings -> Branches. At minimum require pull request reviews before merging, require status checks to pass, and disable force-pushes / deletions. Match the rule to OpenSSF Scorecard's Branch-Protection thresholds for the organization's compliance baseline.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-002: Default branch protection does not require pull request reviews { #scm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``required_pull_request_reviews.required_approving_review_count`` from the branch protection payload. Fires when the field is absent (no review requirement at all) or when the count is 0. ``SCM-001`` covers the case where no protection rule exists; this rule scopes specifically to the review-count knob inside an existing rule.

**Known false-positive modes**

- ``required_pull_request_reviews.bypass_pull_request_allowances`` is covered by ``SCM-018``: a protection rule that requires reviews but lists every contributor in the bypass allowlist still passes this rule even though the control is unenforced in practice. Read SCM-002 + SCM-018 as a pair when auditing whether required review actually fires.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require a pull request before merging`` and set the minimum approving review count to at least 1 (Scorecard's threshold for Branch-Protection's middle tier; raise to 2 for higher trust). Combine with ``Dismiss stale pull request approvals when new commits are pushed`` so a force-push doesn't carry an old approval forward.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-003: GitHub default code scanning is not enabled { #scm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Reads ``state`` from the default code-scanning setup endpoint (``GET /repos/{owner}/{repo}/code-scanning/default-setup``). Fires when ``state`` is anything other than ``configured`` (``not-configured``, missing, or 404). This check only evaluates the default-setup endpoint. Repos running hand-authored CodeQL workflows or third-party SARIF uploads can still fail SCM-003; suppress per repo via ignore-file when that alternative coverage is intentional.

**Known false-positive modes**

- Repos that ship a hand-authored CodeQL workflow (or use Semgrep / Snyk / another SAST whose results land in the Code Scanning UI via SARIF upload) get the same coverage without enabling default setup. Suppress via ignore-file rather than removing the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable default code scanning under the repository's Settings -> Code security -> Code scanning -> Default. The GitHub-managed CodeQL setup picks the right languages automatically and writes findings into the Code Scanning UI on every push and PR. Teams that already ship a CodeQL workflow can leave this rule's check off — but the default setup is the lowest-friction path for repos that don't have one.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-004: GitHub secret scanning is not enabled { #scm-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``security_and_analysis.secret_scanning.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Public repos get secret scanning free since 2023; private repos require a GitHub Advanced Security license. Without secret scanning, a credential committed even briefly is recoverable from git history indefinitely.

**Known false-positive modes**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. The fix is to grant the token admin scope on the repo (or re-run with a personal token from a maintainer) rather than to suppress the rule.

**Seen in the wild**

- GitGuardian's annual State of Secrets Sprawl reports find millions of fresh credential leaks per year across public GitHub commits, with the median time-to-revocation measured in days. Native secret scanning alerts the maintainer within minutes of the push, collapsing the exploitable window from days to minutes for the patterns it covers.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable secret scanning under the repository's Settings -> Code security -> Secret scanning. The GitHub-managed scanner covers ~200 token patterns from major providers and runs on every push. Pair with push protection so secrets are blocked at commit time rather than caught after the fact.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-005: Dependabot security updates are not enabled { #scm-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Known false-positive modes**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-006: Default branch protection does not require signed commits { #scm-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-007: Default branch protection allows force-pushes { #scm-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-471</span>
</div>

Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-008: Default branch protection does not require status checks { #scm-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Known false-positive modes**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-009: Default branch protection allows branch deletion { #scm-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-010: Branch protection allows administrators to bypass { #scm-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-011: Default branch protection does not require CODEOWNERS reviews { #scm-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Known false-positive modes**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-012: Default branch protection keeps stale reviews after a push { #scm-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-367</span>
</div>

Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-013: Default branch protection does not require conversation resolution { #scm-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-014: Default branch protection does not require approval of the most recent push { #scm-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-015: Secret scanning push protection is not enabled { #scm-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``security_and_analysis.secret_scanning_push_protection.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Strongly paired with SCM-004 (secret scanning enabled): SCM-004 catches credentials after the push, SCM-015 stops them at the push. Both should be on for high-trust repos.

**Known false-positive modes**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Push protection covers the GitHub-managed pattern set (~200 token patterns from major providers). Custom-pattern support requires GitHub Advanced Security on private repos; public repos get the GitHub-managed set free.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable secret scanning push protection under the repository's Settings -> Code security -> Push protection. Pushes containing matched credential patterns are refused by GitHub before the commit is accepted, so the credential never enters git history. Authors get an immediate remediation prompt; the bypass-with-justification flow preserves the audit trail when a legitimate test-case credential needs to land.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-016: Private vulnerability reporting is not enabled { #scm-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Reads ``security_and_analysis.private_vulnerability_reporting.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Known false-positive modes**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that publish a SECURITY.md with an alternative out-of-band reporting channel (security@ mailbox, HackerOne / Bugcrowd program) cover the same control via a different mechanism. Suppress via ignore-file when the alternative is in place and documented.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable private vulnerability reporting under the repository's Settings -> Code security -> Private vulnerability reporting. Researchers get a private ``Security`` tab where they can submit details directly to maintainers; the maintainers can then triage, request a CVE, coordinate disclosure timing, and merge a fix without exposing the bug publicly until ready.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-017: Repository has no CODEOWNERS file { #scm-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Known false-positive modes**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-018: Required PR reviews can be bypassed by named identities { #scm-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``required_pull_request_reviews.bypass_pull_request_allowances`` from the branch protection payload. Fires when any of ``users`` / ``teams`` / ``apps`` is non-empty. Surfaces the counts so the operator can locate the bypass entries in the GitHub UI without re-running the audit manually.

**Seen in the wild**

- Multiple GitHub Security Lab writeups attribute post-incident review-control gaps to legacy bypass entries: a contractor onboarded years earlier is listed in the allowance, a compromise of that contractor account merges tampered code despite the team having added required reviews on the default branch.

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, clear ``Allow specified actors to bypass required pull requests`` (``required_pull_request_reviews.bypass_pull_request_allowances`` in the API). Required reviews are only as strong as the bypass list. If a release-bot account needs to merge automated PRs, prefer a separate protection rule for the bot's branch namespace rather than a bypass entry on the default branch.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-019: Push restrictions allowlist names individual users { #scm-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``restrictions.users`` from the branch protection payload. Fires when the list is non-empty. ``restrictions`` itself being absent is the default GitHub posture (no push allowlist; review gates govern access) and passes this rule. Teams and apps in ``restrictions`` are not flagged — the rule audits the personal-account subset specifically.

**Known false-positive modes**

- A break-glass admin account intentionally listed for incident response is a legitimate use case. Suppress via ignore-file once the account's access has been reviewed (MFA, hardware token, audit-logged use).

<div class="pg-rule__rec" markdown>

**Recommended action**

In the default-branch protection rule, audit the ``Restrict who can push to matching branches`` allowlist (``restrictions`` in the API). Move each individual user into a GitHub team and add the team instead, or replace with a GitHub App / bot service account when the entry is an automation. Named user entries are personal-compromise vectors that bypass every PR-review gate on the branch.

</div>

</div>

---

## Adding a new SCM (GitHub / GitLab / Bitbucket) posture check

1. Create a new module at
   `pipeline_check/core/checks/scm/rules/scmNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(snapshot: SCMRepoSnapshot) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``SCMRepoSnapshot``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/scm/SCM-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py scm
   ```
