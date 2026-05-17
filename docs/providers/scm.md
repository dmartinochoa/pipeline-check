# SCM (source control management) posture provider

Scans repository governance via the platform's REST API: branch
protection, required reviews, code scanning, secret scanning,
Dependabot, signed commits, and the rest of the controls that
live at the repo / org settings layer rather than in workflow YAML.
Maps each rule to the OpenSSF Scorecard check it evidences and to
the CIS Software Supply Chain Security Guide section it satisfies.

Three platforms today: **GitHub** (full 28-rule pack), **GitLab**
and **Bitbucket Cloud** (universal subset of seven rules:
``SCM-001``, ``SCM-002``, ``SCM-006``, ``SCM-007``, ``SCM-008``,
``SCM-009``, ``SCM-017``). GitHub-only rules pass on the other
platforms with a "not applicable on PLATFORM" note in the
description so the operator sees the deliberate skip rather than
a silent absence.

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

30 checks · 0 have an autofix patch (``--fix``).

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
| [SCM-020](#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-021](#scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-022](#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-023](#scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-024](#scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-025](#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-026](#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-027](#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-028](#scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-029](#scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-030](#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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

<div class="pg-rule pg-rule--high" markdown>

## SCM-020: Default workflow GITHUB_TOKEN has write permission { #scm-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Reads ``default_workflow_permissions`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. Values are ``"read"`` (safe) or ``"write"`` (fail). Requires the token to have ``admin`` scope on the repo; without it GitHub returns 403 and the rule passes silently with an unavailability note. Complements GHA-048 / GHA-049 — those catch the *workflow* asking for write; SCM-020 catches the *org / repo* handing out write by default.

**Known false-positive modes**

- Repos where every workflow legitimately needs write access (release-publishing automation, mirror-sync jobs) may set the default to ``write`` deliberately. The right pattern is still to keep the default at ``read`` and grant write at the workflow level — that way a new workflow (added by a future contributor) starts safe. Suppress only when every workflow in the repo carries an explicit ``permissions:`` block.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the worm's propagation primitive was a stolen ``GITHUB_TOKEN`` with ``contents: write`` and ``workflows: write``. Repos whose default workflow permissions were ``read`` were unaffected even when their workflows ran a compromised npm dep; ``write``-default repos handed the worm the keys.

<div class="pg-rule__rec" markdown>

**Recommended action**

In repo Settings → Actions → General → Workflow permissions, set the default to ``Read repository contents and packages permissions``. Workflows that genuinely need to push, comment on PRs, or modify issues opt in explicitly via the workflow-file ``permissions:`` block. The default ``write`` setting gives every workflow's ``GITHUB_TOKEN`` write access to every API surface the repo exposes (contents, issues, PRs, actions, packages, deployments), so a single compromised dependency in any job is one step away from the GHA-048 / GHA-049 worm-propagation primitives (workflow self-mutation, cross-repo push) the rule pack catches at the workflow-YAML layer. Setting the default to ``read`` is the org-side complement: even if a workflow forgets to declare ``permissions:`` and the compromised dep tries to push, GitHub refuses the operation.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-021: Actions can approve pull requests (self-approval bypass) { #scm-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-863</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfil the review requirement itself.

**Known false-positive modes**

- Some orgs allow Actions self-approval as part of a tightly-scoped automation flow (e.g., a code-formatter bot that opens-and-merges its own PRs). The safer pattern is to grant the bot a dedicated PAT scoped to PR-create-and-approve, not the repo-wide GITHUB_TOKEN. Suppress only when the trade-off has been documented.

<div class="pg-rule__rec" markdown>

**Recommended action**

In repo Settings → Actions → General → Workflow permissions, uncheck ``Allow GitHub Actions to create and approve pull requests``. With it on, any workflow whose ``GITHUB_TOKEN`` includes ``pull-requests: write`` can submit an approving review on a PR — including its own. Required-review controls (SCM-002), CODEOWNERS reviews (SCM-011), and last-push approval (SCM-014) all become advisory once Actions can satisfy their own gate. A compromised dependency that opens a PR can immediately approve and merge it without any human in the loop.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-022: Repo Actions permissions allow any source (no allow-list) { #scm-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``allowed_actions`` from ``GET /repos/{owner}/{repo}/actions/permissions``. Values: ``"selected"`` (allow-listed) and ``"local_only"`` (org-internal only) pass; ``"all"`` (no restriction) fails. Requires admin scope. The rule passes silently when Actions is disabled at the repo level (``enabled: false``) — nothing runs, so the source restriction is moot.

**Known false-positive modes**

- Repos that legitimately consume a wide variety of third-party actions (open-source CI examples, marketplace-aggregator demos) may accept the ``all`` mode as a trade-off. The right defense in that case is rigorous SHA-pinning (GHA-001) plus the GHA-040..047 reputation pack; SCM-022 is the org-level allow-list that becomes redundant when every workflow already pins to a vetted commit.

<div class="pg-rule__rec" markdown>

**Recommended action**

In repo Settings → Actions → General → Actions permissions, set the allow-list mode to ``Allow <owner>, and select non-<owner>, actions and reusable workflows`` (``selected``) and curate a list of trusted publishers. Each new third-party action becomes an explicit decision rather than the result of a workflow writer adding ``uses: random/unknown@v1`` and CI silently executing it. The shipped pack of GHA-040 (compromised-action registry) plus GHA-041..047 (action reputation checks) provides the workflow-time signal; SCM-022 is the org-policy gate that says ``don't even let an untrusted action onto the runner.``

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-023: Deployment environment lacks required-reviewer protection { #scm-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Walks ``GET /repos/{owner}/{repo}/environments`` and flags every environment whose ``protection_rules`` list doesn't include a rule with ``type == "required_reviewers"``. Passes silently when no environments are configured (``total_count: 0``) — there's nothing to evaluate. Pairs with GHA-050 (the workflow-layer rule that checks ``jobs.<id>.environment:`` is declared) and SCM-024 (deployment-branch-policy on the same environments).

**Known false-positive modes**

- Non-production environments (``preview``, ``staging-ephemeral``) that legitimately auto-deploy without human gate are flagged by this rule, since GitHub doesn't distinguish environment severity. Suppress on those specific environment names with a rationale rather than disabling the rule for the whole repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure required reviewers on every deployment environment (Settings → Environments → <name> → ``Required reviewers``). Pick a team or set of users who must approve each deployment job that targets the environment. Without a required-reviewer protection rule, any workflow run with the right environment name in its ``jobs.<id>.environment:`` block can deploy without human gate — the exact primitive GHA-050 (publish without OIDC + environment) catches at the workflow layer. SCM-023 is the org-level complement: a workflow that *declares* an environment still needs the environment itself to enforce the gate.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-024: Deployment environment can deploy from any branch { #scm-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-862</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` (with at least one configured policy) passes. Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

**Known false-positive modes**

- Test / preview environments often accept any branch by design (the whole point is to validate feature branches before merging). Suppress on those specific environment names; treat the rule as production-scoped.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a deployment-branch policy on every environment (Settings → Environments → <name> → ``Deployment branches and tags``). Pick ``Protected branches only`` for production-like environments so a workflow run on a feature branch cannot push to production. The combination ``required reviewers`` (SCM-023) + ``deployment branch policy`` (SCM-024) is the deploy-gate the rest of the rule pack (GHA-050 publish-without-OIDC, SCM-001 branch protection) assumes is in place; without SCM-024, a workflow on any branch can target the production environment and reviewers approve a stale or wrong-branch deployment without realizing.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-025: Repo has write-enabled deploy keys (push backdoor) { #scm-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``GET /repos/{owner}/{repo}/keys`` and flags every deploy key whose ``read_only`` field is false. Requires ``admin`` scope on the repo; without it GitHub returns 403 / 404 and the rule passes silently with an unavailability note. Deploy keys come in two shapes: read-only (clone access only, safe equivalent of a public-fork checkout) and write-enabled (push access, the failure case this rule catches). The endpoint returns the SSH public key plus metadata, never the private half — the scan can't recover the credential, only enumerate which keys exist and what scope each carries.

Complements every branch-protection rule in the pack: without SCM-025, an unaudited write deploy key bypasses the entire control set the other rules document. Also pairs with SCM-018 (PR-review bypass allowance) and SCM-019 (push-restriction allowlist), which catch the same risk shape on the user / team side.

**Known false-positive modes**

- Some CI flows legitimately use a write deploy key for release tagging or auto-generated docs commits. The right pattern is a GitHub App or a fine-grained PAT with an audit trail; deploy keys persist indefinitely and leave no record of who used them. Suppress with a one-line rationale that names the specific key title.

**Seen in the wild**

- Long-running pattern of forgotten deploy keys retaining write access years after the original owner left an org. Public catalogs of leaked SSH private keys on paste sites and GitHub itself routinely hit configured deploy keys; the corresponding repo is push-compromised until the operator revokes the key.

<div class="pg-rule__rec" markdown>

**Recommended action**

Convert every deploy key to read-only (Settings → Deploy keys → uncheck ``Allow write access``), then rotate the underlying SSH key pair if the previous holder no longer needs write access. Deploy keys are repo-scoped SSH credentials that bypass GitHub's normal RBAC — anyone with the private half can push directly, side-stepping branch protection (SCM-001), required reviews (SCM-002), CODEOWNERS (SCM-011), and the user-account audit trail. If the use case genuinely needs push (a CI runner that tags releases, a release-bot account), prefer a fine-grained PAT or a GitHub App with constrained scope, both of which carry user-visible audit-log entries that deploy keys do not.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-026: Webhook ships events insecurely (HTTP / no-TLS / no-secret) { #scm-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``GET /repos/{owner}/{repo}/hooks`` and flags any active webhook with one or more failure modes:

* ``config.url`` starts with ``http://`` — push payloads   including code diffs leak over plain HTTP
* ``config.insecure_ssl == "1"`` — TLS certificate   verification disabled, MITM possible on the HTTPS   endpoint
* ``config.secret`` is null / missing — no HMAC   signature, so anyone who learns the URL can forge   events into the receiver

Inactive webhooks (``active: false``) are skipped — they don't fire. Each finding's description lists every failure mode hit so the operator sees the full fix scope per webhook. Requires admin scope; without it the endpoint returns 403 / 404 and the rule passes silently. GitHub never returns the actual secret value via the API; the slot reports either ``"********"`` (configured) or ``null`` (missing), so this rule detects the absence without ever handling the credential itself.

**Known false-positive modes**

- Long-running internal-only webhooks pointing at a hostname only resolvable inside a private network (``http://internal.svc/hook``) often skip TLS by convention. The right fix is still to terminate TLS at an ingress and use a non-empty secret; the rule does not have visibility into network topology and cannot distinguish 'public HTTP' from 'private-network HTTP', so it errs toward flagging. Suppress per webhook id with a rationale that names the receiving service.

**Seen in the wild**

- Long-running pattern of webhook payloads leaking via plain-HTTP receivers (Zapier, IFTTT, custom legacy endpoints) — the GitHub repo's commit-diff content, pull-request body, and secret-scanning alert payloads all land on the wire unencrypted. Public catalogs of compromised internal webhooks document the receiver-side breach where the URL alone was enough to inject forged events when no shared secret was configured.

<div class="pg-rule__rec" markdown>

**Recommended action**

For each flagged webhook, fix all three knobs at once (Settings → Webhooks → <hook> → Edit):

* Switch the Payload URL to ``https://`` and enable ``Verify SSL`` (the field is labeled ``SSL verification`` on the form; setting it to ``Enable SSL verification`` is the safe value).
* Set the ``Secret`` field to a long random value and validate the incoming ``X-Hub-Signature-256`` header on the receiving end. Without the secret + verification, an attacker who learns the URL (URLs are not secrets; they appear in receiving-system logs, in CI screenshots, in support tickets) can forge events.

If the receiving service genuinely cannot handle HTTPS or shared secrets, terminate TLS at a reverse proxy in front of the receiver and keep the public-facing URL ``https://`` with a real cert. The webhook content carries the full event payload — pull requests with diff content, push events with the commits, secret scanning alerts — which is exactly what an unauthenticated MITM is looking for.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-027: Outside collaborator holds write / maintain / admin access { #scm-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-ACCESS-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Walks ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside`` and flags every entry whose ``permissions`` block has any of ``admin: true``, ``maintain: true``, or ``push: true``. Read-only (``permissions.pull: true`` with no higher tier) and triage entries pass. Each finding's description names every elevated collaborator with the granular level so the operator can prioritize.

Requires admin scope on the repo to enumerate the outside-collaborator list; without it the endpoint returns 403 and the rule passes silently with an unavailability note. The hydrator fetches a single page (``per_page=100``); in the rare case of more than 100 outside collaborators on one repo, the description appends a truncation note and asks for a manual audit.

**Known false-positive modes**

- Some flows legitimately grant write access to a vetted outside collaborator on a short-term basis (audit firm, incident responder, vendor escalation). The right compensating control is a calendar-bound suppression with the rationale and the expected revocation date; the rule itself should keep flagging the access so the revocation date is visible at every scan.

**Seen in the wild**

- Long-running pattern across compromise postmortems: a former contributor's outside-collaborator entry retains ``push`` access years after the engagement ended. The account is then taken over (often by credential stuffing or a leaked PAT), and the attacker pushes a tampered commit that lands without review because the access level itself is the gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit Settings → Collaborators and teams → Outside collaborators. For each entry the rule flagged: either (a) downgrade the access to ``Read`` if the contributor only needs to clone / open PRs, or (b) move the account into the org as a member (so the org's centralized RBAC, SCIM, and access-review processes apply) before granting write access. Outside collaborators bypass the org's user-lifecycle controls: when the contractor's term ends, the entry stays until somebody manually removes it. A compromised outside-collab account with ``push`` access is the direct path to bypassing branch protection: that account can push code that SCM-021 (Actions self-approval) or SCM-018 (PR bypass allowance) clears through every required-review gate. Maintain / admin extends the blast radius to repo-config control.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-028: Private repo allows forking { #scm-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-ACCESS-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Reads ``private`` and ``allow_forking`` from the repo metadata. Fires when both are ``true``. Public repos (``private: false``) pass — forking a public repo is expected. Repos that explicitly disable forking (``allow_forking: false``) pass regardless of visibility. The fork-vs-Actions-secret-leak interaction is the operational risk: a fork PR using ``pull_request_target`` runs with the *base* repo's secrets, so a fork carries both the code and a path to the secrets if the workflow surface is permissive. Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers) at the workflow layer; SCM-028 is the org-policy gate.

**Known false-positive modes**

- Org-wide development workflows that require contributors to fork-and-PR within the company (rather than push to branches in the original repo) legitimately rely on ``allow_forking: true`` for private repos. The right compensating control is the workflow-side hardening: GHA-027 / GHA-046 / SCM-021 (Actions self-approval off) together keep the secret-leak surface closed even when forks are allowed. Suppress with a rationale that names the contribution workflow.

<div class="pg-rule__rec" markdown>

**Recommended action**

In repo Settings → General → Features, uncheck ``Allow forking``. The setting only opens the trapdoor if you actually use ``pull_request_target`` or trigger workflows on fork PRs, but every private-repo fork carries the code into the forker's personal namespace (which has its own visibility surface — public profile, weaker 2FA enforcement, separate token scope). Even without the Actions-secret leak surface, allowing forks of a private repo means a compromised user account that had access at any point can preserve a copy of the intellectual property indefinitely.

If forks are genuinely needed for the development workflow, enforce ``Allow forking`` at the org level and pair it with GHA-046 (block manual PR-head fetches on untrusted-trigger workflows) and GHA-027 (no ``pull_request_target`` on untrusted input) so the secret-leak surface stays closed at the workflow layer.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-029: Repository ruleset is in evaluate / disabled mode (not enforced) { #scm-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-693</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Walks ``GET /repos/{owner}/{repo}/rulesets`` and flags every entry whose ``enforcement`` is anything other than ``"active"``. Two failure shapes are typical:

* ``enforcement: "evaluate"`` — preview / dry-run mode;   the ruleset logic runs but doesn't block.
* ``enforcement: "disabled"`` — explicit off; rule   exists in the UI but takes no effect.

Passes silently when no rulesets are configured (``[]``); in that case the SCM-001..010 legacy branch-protection rules carry the governance load. Requires admin scope on the repo; without it the endpoint returns 403 / 404 and the rule passes silently with an unavailability note.

**Known false-positive modes**

- A freshly-authored ruleset legitimately sits in ``evaluate`` mode for a short audit window before promotion to ``active``. Suppress for that specific ruleset id with a calendar-bound rationale; the rule should keep flagging until the promotion lands so the transition window doesn't quietly become permanent.

<div class="pg-rule__rec" markdown>

**Recommended action**

Flip every non-enforcing ruleset to ``enforcement: active`` (Settings → Rules → Rulesets → <name> → Enforcement status → Active). The ``evaluate`` mode is intentionally permissive: it runs the rule logic and surfaces what *would* have been blocked, but it never actually blocks the push, merge, or commit. ``disabled`` is the explicit off-switch. Both modes silently document intent without enforcing the policy — operators commonly create rulesets in ``evaluate`` to preview their effect and forget to flip them, leaving the repo with the audit appearance of governance and the behavior of none.

Note: the legacy-branch-protection rules in this pack (SCM-001..010) do NOT see rulesets. An org that has fully migrated to rulesets can pass the entire SCM-NNN legacy pack while every actual governance signal is in evaluate mode.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-030: Repository ruleset has bypass actor with bypass_mode: always { #scm-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For each ``active`` ruleset, walks ``bypass_actors`` (populated by the per-ruleset detail fetch) and flags every entry with ``bypass_mode: "always"`` whose ``actor_type`` is not ``"Integration"`` (GitHub Apps). Non-app actors are listed by ``actor_type`` + ``actor_id``; the rule does not resolve those IDs to human-readable names (that would require another API round-trip per actor; the operator already sees the names in the UI when they go to fix it).

Rulesets in non-active enforcement modes are skipped — SCM-029 owns the not-enforced-at-all case and a non-active ruleset's bypass list is moot since the rules don't run anyway. Integration bypasses pass: a scoped GitHub App is a typical legitimate emergency-fix channel and shipping the bypass through the App's audit flow is the documented pattern. Requires admin scope; without it the ruleset-detail endpoint returns 403 / 404 and the rule passes silently.

**Known false-positive modes**

- Some orgs grant ``always`` bypass to a tightly-scoped automation team for after-hours emergency response. The right pattern is a GitHub App with auditable triggering (PagerDuty, Slack); ``always`` bypass for a human team leaves no record of the override. Suppress on the specific ruleset id with a calendar-bound rationale that names the audit channel and the next promotion review.

<div class="pg-rule__rec" markdown>

**Recommended action**

For every bypass actor flagged, switch ``bypass_mode`` from ``always`` to ``pull_request`` in the ruleset configuration (Settings → Rules → <ruleset> → Bypass list → <actor> → Bypass mode). The ``pull_request`` mode requires the bypass to be requested via a PR review thread, which leaves an audit trail and gives reviewers a chance to push back. ``always`` mode is an unaudited override: the actor pushes / merges as if the ruleset weren't there, and no record names who or why. If the bypass is genuinely needed for emergency response, scope it to a specific GitHub App (the rule does not flag ``Integration`` bypasses by default) rather than a human role; an App is callable through your existing ticketing / approval flow.

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
