# SCM posture: GitHub

Scans GitHub repository governance via the REST API: branch
protection, required reviews, code scanning, secret scanning,
Dependabot, signed commits, rulesets, environments, deploy keys,
webhooks, outside collaborators, and the rest of the controls that
live at the repo / org settings layer rather than in workflow YAML.

GitHub runs the full SCM rule pack (49 rules). The seven universal
rules shared with [GitLab](scm_gitlab.md) and
[Bitbucket](scm_bitbucket.md) are: ``SCM-001``, ``SCM-002``,
``SCM-006``, ``SCM-007``, ``SCM-008``, ``SCM-009``, ``SCM-017``.
All other rules are GitHub-only. GitHub-only rules pass on the
other platforms with a "not applicable on PLATFORM" note so the
operator sees the deliberate skip rather than a silent absence.

## Producer workflow

```bash
# Token comes from --gh-token or $GITHUB_TOKEN. Without admin
# scope on the repo, security_and_analysis features (SCM-004 /
# SCM-005 / SCM-015 / SCM-016) cannot distinguish "really
# disabled" from "I lacked visibility" — re-run with admin scope
# to confirm those rules' verdicts.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world

# Offline / CI mode: read JSON responses from disk instead of
# hitting the network.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world \
    --scm-fixture-dir ./scm-fixtures/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

## Token permissions

Pass the token via ``--gh-token`` or ``$GITHUB_TOKEN``. Classic PAT
scopes and fine-grained PAT permissions are listed side-by-side; on
GitHub Enterprise Cloud the fine-grained permissions also map to
the same names on a GitHub App installation token.

| Tier | Classic PAT scope | Fine-grained PAT / GitHub App | Rules unlocked |
|------|-------------------|-------------------------------|----------------|
| public (no token) | — | — | SCM-001, -002, -006, -007, -008, -009, -017 on public repos; rate-limited to 60 req/hr |
| read (public + private) | ``repo`` (or ``public_repo`` for public-only) | ``Metadata: read`` + ``Contents: read`` | adds private-repo coverage for the universal rules; raises rate limit to 5000 req/hr |
| admin | ``repo`` + ``admin:repo_hook`` + ``read:org`` | ``Administration: read`` + ``Webhooks: read`` + ``Members: read`` + ``Environments: read`` + ``Code scanning alerts: read`` | adds SCM-003, -004, -005, -010..016, -018, -019, -020, -021, -022, -023, -024, -025, -026, -027, -028, -029..047 |

### Per-rule scope notes

Admin-tier rules only; the universal rules work at read tier.

  * **SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016** read
    ``security_and_analysis.<feature>.status`` from the repo
    metadata payload. GitHub omits the entire
    ``security_and_analysis`` block unless the token has admin
    scope on the repo, so without it the rules cannot tell
    ``disabled`` from ``unknown`` and pass with an unavailability
    note.
  * **SCM-010 / SCM-011 / SCM-012 / SCM-013 / SCM-014 / SCM-018 /
    SCM-019** read GitHub-only protection-payload knobs
    (``enforce_admins``, ``require_code_owner_reviews``,
    ``dismiss_stale_reviews``, ``required_conversation_resolution``,
    ``require_last_push_approval``,
    ``bypass_pull_request_allowances``, ``restrictions``). The
    branch-protection endpoint returns these only when the token
    has at least ``Administration: read`` (fine-grained) / ``repo``
    scope (classic).
  * **SCM-020 / SCM-021 / SCM-022** hit
    ``/actions/permissions`` and ``/actions/permissions/workflow``.
    Both require ``Administration: read``.
  * **SCM-023 / SCM-024** walk ``/environments``. Requires
    ``Environments: read``.
  * **SCM-025** reads ``/keys`` (deploy keys). Requires
    ``Administration: read``.
  * **SCM-026** reads ``/hooks`` (webhooks). Requires
    ``Webhooks: read``.
  * **SCM-027** reads ``/collaborators?affiliation=outside``.
    Requires ``Members: read`` on the org; ``Administration: read``
    on the repo is the per-repo equivalent.
  * **SCM-028** reads ``private`` and ``allow_forking`` from the
    repo metadata. Available at read tier (no admin needed).
  * **SCM-029, SCM-030, SCM-032..SCM-042** walk ``/rulesets`` and
    the per-ruleset detail endpoint. Both require
    ``Administration: read``.
  * **SCM-043 / SCM-044** read tag-targeted rulesets / branch
    protection ``required_signatures`` + ``enforce_admins``.
    Requires ``Administration: read``.
  * **SCM-045 / SCM-046 / SCM-047** read the code-scanning
    default-setup endpoint and the languages endpoint. Requires
    ``Code scanning alerts: read``; the languages endpoint is
    available at read tier.

GitHub Apps: the same fine-grained permission names apply to App
installation tokens. The App needs to be installed on the target
repo (or org); installation-only access is enough for repo-scoped
endpoints. ``Members: read`` is org-level; install the App on the
org to enumerate outside collaborators.

## What the rules expect

The provider hits these endpoints per repo:

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

### FP-prevention guards

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

55 checks · 0 have an autofix patch (``--fix``).

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
| [SCM-031](#scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-032](#scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-033](#scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-034](#scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-035](#scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-036](#scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-037](#scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-038](#scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-039](#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-040](#scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-041](#scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-042](#scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-043](#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-044](#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-045](#scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-046](#scm-046) | Default code scanning has no periodic scan schedule | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [SCM-047](#scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-048](#scm-048) | Org codespace secret scoped to all repos | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-049](#scm-049) | Classic PAT used where a fine-grained token suffices | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-050](#scm-050) | GitLab push rules do not block secret-shaped commits | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-051](#scm-051) | GitLab push rules do not enforce committer-email check | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-052](#scm-052) | GitLab merge requests can land with unresolved discussions | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SCM-053](#scm-053) | GitLab merge requests allow the author to approve their own MR | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-054](#scm-054) | Bitbucket private repo allows public forks | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SCM-055](#scm-055) | Bitbucket default branch has no write-side restriction kinds | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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

Reads ``enabled`` from the dedicated ``GET /repos/{owner}/{repo}/private-vulnerability-reporting`` endpoint (private vulnerability reporting is not part of the repo ``security_and_analysis`` block). Fires when the endpoint reports ``enabled: false``; passes with an unavailability note when the endpoint can't be reached so it doesn't fire on every repo. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Known false-positive modes**

- When the endpoint is unreachable (the token lacks the scope to read it, or a GitHub Enterprise Server version predates the feature), this rule cannot tell ``disabled`` from ``unknown`` and passes with an unavailability note. Re-run with a sufficiently scoped token to confirm.
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

Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfill the review requirement itself.

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

Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` passes. (Custom policies with zero patterns block every branch, so the boolean flag alone is a safe pass.) Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

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

<div class="pg-rule pg-rule--medium" markdown>

## SCM-031: Repo allows auto-merge (no human-timing gate) { #scm-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-693</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Reads ``allow_auto_merge`` from the repo metadata (already fetched by every SCM scan; no extra endpoint). Fires when the value is ``true``. A missing field is treated as the GitHub default (``false``) and passes. The check is intentionally orthogonal to whether reviews are required — auto-merge with strong required-review controls is sometimes acceptable, auto-merge with weak ones is not. SCM-031 surfaces the trade-off; the operator pairs the finding with the SCM-002 / SCM-011 / SCM-014 / SCM-021 status to decide whether to keep auto-merge.

**Known false-positive modes**

- High-throughput engineering orgs that pair auto-merge with rigorous required-reviews + CODEOWNERS + last-push approval + no-Actions-self-approval (SCM-021) legitimately depend on auto-merge for velocity. The right pattern is to suppress this rule with a rationale that names the compensating controls so the trade-off stays visible at every audit. Suppressing without naming the controls makes the trade-off invisible to the next reviewer.

<div class="pg-rule__rec" markdown>

**Recommended action**

In repo Settings → General → Pull Requests, uncheck ``Allow auto-merge``. With auto-merge on, the PR merges the moment its required checks pass — including any required reviews already on the PR — with no further human gate on *when* the merge happens. The risk is compositional: combined with SCM-021 (Actions can self-approve PRs) or SCM-018 (PR-review bypass allowance), a workflow that opens a PR, satisfies its own required-review gate, and waits for status checks lands code into main without a human ever looking at the diff at the merge moment. If the workflow itself is what was compromised (Shai-Hulud, postinstall worm), the auto-merge step is the last gate that didn't fire.

If your team relies on auto-merge for throughput, the compensating controls are SCM-021 (Actions cannot self-approve), SCM-002 (required reviews ≥ 1), SCM-011 (CODEOWNERS reviews required), and SCM-014 (last-push approval) — all together. Without all four, auto-merge is the path of least resistance for an unauthored commit to reach main.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-032: Active ruleset doesn't require a PR review (governance theater) { #scm-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Across the active rulesets targeting the default branch, looks for an entry with ``type: "pull_request"`` whose ``parameters.required_approving_review_count`` is at least 1. Fires only when none of them carries one (GitHub aggregates rules across every ruleset targeting a ref). Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced with an evaluation-gap note (the same pattern SCM-030 uses). Tag- and push-targeted rulesets are ignored (they don't protect branches).

Pairs with SCM-002 (legacy branch-protection required reviews) and SCM-029 (ruleset not enforced). The three rules together cover the required-review surface: SCM-002 for legacy BP, SCM-029 for the existence of an active ruleset, SCM-032 for whether that ruleset actually requires a PR.

**Known false-positive modes**

- Some rulesets are deliberately scoped to enforce only non-PR-review controls (e.g., a ``commit_message_pattern`` ruleset for changelog compliance, or a ``tag_name_pattern`` ruleset for release tagging). The right pattern is to ALSO have a separate ruleset that enforces PR reviews on the same refs; SCM-032 fires when the *combination* leaves a gap. Suppress on the specific ruleset id with a rationale that names the PR-review channel (separate ruleset or legacy branch protection).

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``pull_request`` rule to every active ruleset and set ``parameters.required_approving_review_count`` to at least 1 (Settings → Rules → <ruleset> → Add rule → Require a pull request before merging → Required approvals). An active ruleset without a PR-review gate is the same shape as legacy branch protection without required reviews (SCM-002): the ruleset is enforced — force-push denial, signed commits, status checks may all fire — but pushes / merges still go through without human review. Operators commonly create rulesets for specific governance signals (e.g., commit-message patterns for compliance) and forget that the PR-review gate is a separate rule type that has to be added explicitly.

SCM-032 aggregates across rulesets the way GitHub does: the default branch is covered when any ruleset targeting it carries a PR-review rule, so a layered config (an org-level ruleset that requires reviews plus a repo-level ruleset that only enforces a commit-message pattern) passes. It fires only when no ruleset targeting the default branch requires a PR review. It stays within the ruleset layer and doesn't consult legacy branch protection; SCM-002 covers that side, and the two together describe the full review-control surface.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-033: Active ruleset doesn't require status checks { #scm-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--esf">ESF-D-CI-COVERAGE</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_status_checks"`` whose ``parameters.required_status_checks`` lists at least one context. Empty lists are treated as no rule. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced explicitly. Passes silently when no rulesets are configured (legacy branch-protection SCM-008 covers the gap).

**Known false-positive modes**

- Some rulesets are deliberately scoped to non-CI concerns (commit-message format, tag-name pattern); those should be paired with a separate ruleset that enforces status checks on the same refs. Suppress with a rationale that names the parallel ruleset.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``required_status_checks`` rule to every active ruleset and populate ``parameters.required_status_checks`` with the names of the contexts that must pass (Settings → Rules → <ruleset> → Add rule → Require status checks to pass before merging → pick the specific check runs). Without it, the ruleset is enforced but pushes / merges land without any of your tests, lint, security scans, or build verification actually being green — the ruleset documents that checks *exist* without requiring them to *pass*. The ruleset analog of SCM-008 (legacy branch-protection required checks).

An empty contexts list (``required_status_checks: []``) is the same as no rule — it documents the gate without filling it. Pick at least one canonical job name (the primary build) and add the rest of your CI matrix over time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-034: Active ruleset doesn't block force-push { #scm-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-471</span>
</div>

For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "non_fast_forward"``. Presence of the rule means force-pushes are blocked on the refs the ruleset targets. Passes silently when no rulesets are configured (legacy SCM-007 covers the gap).

**Known false-positive modes**

- Release-engineering rulesets sometimes deliberately allow force-push on a specific tag-pattern target (e.g. moving release tags). Suppress on the specific ruleset id with a rationale that names the target pattern.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``non_fast_forward`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Block force pushes). Without it, a force-push rewrites history on the target branch — commits that previously appeared in the audit trail disappear from the surface log, and anyone with push access can erase evidence of an earlier action. The ruleset analog of SCM-007 (legacy branch-protection force-push denial). Pair with SCM-006 (signed commits) so even a rewrite leaves verifiable signatures on the surviving commits.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-035: Active ruleset doesn't block branch deletion { #scm-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-471</span>
</div>

For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "deletion"``. Presence of the rule means deletion is blocked. Passes silently when no rulesets are configured (legacy SCM-009 covers the gap).

**Known false-positive modes**

- Rulesets that target ephemeral preview / feature branches legitimately allow deletion. Suppress on the specific ruleset id with a rationale that names the target pattern.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``deletion`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Restrict deletions). Without it, anyone with push access to a ref the ruleset targets can delete that ref. The ruleset analog of SCM-009 (legacy branch-protection branch deletion denial). Mostly a hygiene control — deleted commits are recoverable from the reflog until garbage collection — but loss of the default-branch ref is a real operational disruption.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-036: Active ruleset doesn't require signed commits { #scm-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_signatures"``. Presence means commits to the targeted refs must carry a valid signature. Passes silently when no rulesets are configured (legacy SCM-006 covers the gap).

**Known false-positive modes**

- Teams that haven't yet rolled out signing keys for all contributors sometimes ship without signature enforcement to avoid blocking ordinary PRs. The right pattern is a phased rollout (configure the rule in ``evaluate`` mode first, then flip to ``active`` once contributors have their keys). Suppress with a rationale that names the rollout date.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``required_signatures`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require signed commits). Without it, a compromised contributor account (or a stolen PAT) can push commits that appear to originate from any author the attacker names in the commit metadata. The signature requirement ties each commit to a key the contributor controls (SSH / GPG / sigstore via gitsign), so post-incident the audit log shows which commits were signed by the key vs forged. The ruleset analog of SCM-006 (legacy branch-protection signed-commit enforcement).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-037: Active ruleset's pull_request rule doesn't dismiss stale reviews { #scm-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

For every active ruleset with a ``pull_request`` rule, checks ``parameters.dismiss_stale_reviews_on_push`` is ``true``. Skips rulesets that don't have a ``pull_request`` rule at all — SCM-032 owns that surface. Passes silently when no rulesets are configured (legacy SCM-012 covers the gap).

**Known false-positive modes**

- Some workflows use ephemeral review-bot accounts that auto-re-approve after push; dismissing on push then re-issuing the approval is the documented pattern. The rule still fires (the dismissal happens) and the re-approval lands separately. If your team operates a different review-velocity flow, suppress with a rationale that names the re-approval channel.

<div class="pg-rule__rec" markdown>

**Recommended action**

On every active ruleset's ``pull_request`` rule, set ``parameters.dismiss_stale_reviews_on_push: true`` (Settings → Rules → <ruleset> → Require a pull request before merging → Dismiss stale pull request approvals when new commits are pushed). Without it, an attacker can land an approving review on a benign early version of the PR, then force-push (if not blocked by SCM-034) or otherwise update the head with malicious commits, and the original approval still counts toward the required-review gate.

The ruleset analog of SCM-012 (legacy branch-protection stale-review dismissal). Pair with SCM-032 (PR-review presence) — without dismissal, the review-count gate documents intent rather than reality once the PR has diverged from the approved state.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-038: Active ruleset doesn't require linear history { #scm-038 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_linear_history"``. Presence means merge commits to the targeted refs are rejected (only fast-forward / rebase / squash integration is allowed). Passes silently when no rulesets are configured — linear history has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Known false-positive modes**

- Teams that prefer merge commits as a deliberate policy (e.g. to preserve the shape of long-lived feature branches in the history) legitimately ship without this rule. Suppress with a rationale that names the merge-strategy policy. The rule is a hygiene / auditability control, not a hard security gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``required_linear_history`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require linear history). Without it, merges into the targeted refs can introduce merge commits, which produce a branching history where two ancestors share authorship of the merge result. Linear history forces rebase- or squash-style integration so every commit on the trunk has a single parent and a single attributable author. This pairs with SCM-036 (signed commits) to give post-incident forensics a clean answer to *who wrote this code and when*: each commit on main has one signature, one author, one parent, one timestamp.

Merge commits aren't a direct attacker primitive — force-push (SCM-034) is the history-rewrite surface — but they obscure git-bisect and complicate ``git log --first-parent`` triage during an incident, and they hide which specific commits landed when a long-lived feature branch is merged.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-039: Active ruleset doesn't pin a required workflow { #scm-039 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--esf">ESF-D-CI-COVERAGE</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "workflows"`` whose ``parameters.workflows`` is a non-empty list. An empty workflows list is treated as no rule (it documents the gate without filling it). Passes silently when no rulesets are configured — required workflows have no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Known false-positive modes**

- Repos that don't run any workflow-based gating at all (pure code-review + signed-commits posture) legitimately ship without this rule. Suppress with a rationale that names the compensating controls. The rule fires LOW because most teams' security posture comes from status-checks (SCM-033); the workflows rule is the stricter scan-removal-resistant variant.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``workflows`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require workflows to pass before merging) and pin at least one workflow by repository + path + ref. The ``workflows`` ruleset rule differs from ``required_status_checks`` (SCM-033) in a load-bearing way: status checks gate on a context *name* that the workflow chooses to report — if the PR edits the workflow YAML to remove or rename that context, the check vanishes and the gate documents intent rather than reality. The ``workflows`` rule pins the workflow file at a vetted ref (``main`` or a specific SHA) and forces *that* workflow to run against the PR's code regardless of what the PR did to the workflow YAML in its own branch. Closes the scan-removal supply-chain shape (attacker opens a PR that deletes ``.github/workflows/security-scan.yml`` and submits malicious code in the same PR).

Pin the workflow ref to either a long-lived branch the ruleset bypass actors don't have write access to or a specific SHA. A ref pinned to a branch the PR author controls undoes the protection.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-040: Active ruleset doesn't gate on code scanning results { #scm-040 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--esf">ESF-D-CI-COVERAGE</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "code_scanning"`` whose ``parameters.code_scanning_tools`` lists at least one tool. An empty tools list documents the gate without filling it and is treated as no rule. Passes silently when no rulesets are configured — the rule_type is ruleset-only and has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Known false-positive modes**

- GHAS-licensing constraint: the ``code_scanning`` ruleset rule type requires GitHub Advanced Security on the repo. Repos on free / team tier can't configure this rule even when they run code scanning via third-party tools. Suppress with the licensing rationale and ensure SCM-033 carries the merge gate via the scan tool's reported status-check context.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``code_scanning`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require code scanning results) and pin at least one tool (CodeQL, the most common choice) with a non-empty alerts threshold. The rule turns a passive code-scanning configuration (SCM-003 — default setup is on) into an active merge gate: the PR can't merge until the scan completes for the head SHA *and* the configured threshold isn't crossed (e.g. ``security_alerts_threshold: "high_or_higher"`` rejects merges that introduce high-severity findings). Closes the asymmetry between code scanning being enabled and the org actually blocking on its results.

If your org doesn't license GHAS (the underlying feature), this rule type isn't available. Suppress with a rationale that names the licensing constraint and carry the gate via ``required_status_checks`` (SCM-033) pointed at the named context the scan tool reports.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-041: Active ruleset doesn't gate on a deployment environment { #scm-041 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_deployments"`` whose ``parameters.required_deployment_environments`` lists at least one environment. Empty lists are treated as no rule. Passes silently when no rulesets are configured — required-deployments enforcement has no legacy branch-protection analog in this scanner's coverage and is not separately evaluated.

**Known false-positive modes**

- Repos that don't have GitHub deployment environments configured (or that gate via status-checks SCM-033 pointed at a deploy job's reported context) legitimately ship without this rule. Suppress with a rationale that names the compensating control. The rule fires LOW because most teams' deployment gating comes from the environment configuration itself (SCM-023, SCM-024); SCM-041 is the merge-side complement that closes the gap when an environment exists but isn't named in any ruleset.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``required_deployments`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require deployments to succeed before merging) and pin at least one environment (typically the staging environment that a CI pipeline deploys the PR's commit to). Pairs with SCM-023 (env reviewers) and SCM-024 (env branch policy): SCM-023/024 ensure the environment itself is gated; SCM-041 makes a successful deployment to that environment a merge prerequisite. Without it, a PR can merge into the default branch without a smoke-test deployment having run, even when the environment is rigorously configured. The ruleset analog of legacy branch protection's ``required_deployments`` checkbox.

An empty environments list (``required_deployment_environments: []``) documents the gate without filling it and is treated as no rule. Pick at least one environment name (typically ``staging`` or ``preview``) so the rule actually gates.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-042: Active ruleset doesn't require merge queue { #scm-042 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-362</span>
</div>

For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "merge_queue"``. Presence means merges to the targeted refs must enter the queue. Passes silently when no rulesets are configured — merge queue has no legacy branch-protection analog (the feature is ruleset-only).

**Known false-positive modes**

- Low-throughput repos (one or two PRs landing per day) don't typically hit the merge-race shape this rule addresses; the operational cost of a merge queue can outweigh the benefit. Suppress with a rationale that names the merge-velocity profile. The rule fires LOW because most teams' CI integrity comes from status-checks (SCM-033); merge_queue is the additional concurrency-hardening control.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``merge_queue`` rule to every active ruleset that covers a high-throughput trunk (Settings → Rules → <ruleset> → Add rule → Require merge queue). Without it, two PRs that each pass ``required_status_checks`` (SCM-033) independently can both merge into the same trunk and produce a state where the combined diff wasn't actually validated — a class of integration regressions that CI on the individual PRs can't catch. The merge queue serializes merges and re-runs the configured checks against the queue's post-merge candidate commit before the merge lands, so the trunk always reflects a tested state.

Pair with SCM-033 (required status checks). SCM-033 ensures CI passes BEFORE merge; SCM-042's merge queue ensures CI passes AFTER merge in queue order. The two gates address different failure modes — the queue closes the merge-race surface that per-PR CI can't see.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-043: Tag-targeted ruleset doesn't require signed commits { #scm-043 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Iterates active rulesets where ``target == "tag"`` and fires when none enforce ``required_signatures`` on the tag refs they cover. Passes silently when no tag-targeted rulesets exist at all (a separate gap: there's no tag protection to evaluate).

**Known false-positive modes**

- Repos that sign tags via a release workflow rather than the ruleset gate (e.g. ``cosign sign`` on the release artifact) get equivalent provenance. Suppress per repo with a rationale that names the workflow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``required_signatures`` rule to every active ruleset whose ``target == tag`` (Settings → Rules → <ruleset> → Add rule → Require signed commits). Tag objects under a release-like glob (``refs/tags/v*`` or ``refs/tags/**``) are downstream consumers' lookup keys; an unsigned tag means a stolen PAT can stamp a release with arbitrary author metadata while the branch-side signing requirement (SCM-006 / SCM-036) passes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-044: Default-branch signed-commits requirement bypassed for admins { #scm-044 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires when ``required_signatures.enabled == True`` and ``enforce_admins.enabled`` is missing or ``False``. The rule passes silently in three cases: when signed commits aren't required at all (SCM-006 owns that surface), when branch protection is missing entirely (SCM-001), and when the repo is archived (read-only, so no unsigned push is possible).

**Known false-positive modes**

- Solo-maintainer repos where the single admin is also the only signing-key holder may turn off enforce_admins to self-recover from a lost key. Suppress per repo with a rationale that names the recovery workflow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable ``Include administrators`` (``enforce_admins``) on the default-branch protection rule so the signed-commit requirement applies to admins too. Alternatively, migrate the requirement into a repository ruleset where bypass actors are explicit and auditable — admin bypass via the legacy protection knob is implicit, while a ruleset bypass list names each actor and is visible in the audit log (see SCM-030 for the ruleset-side bypass check).

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-045: Default code scanning uses the limited query suite { #scm-045 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Reads ``query_suite`` from the default code-scanning setup endpoint. Fires only when ``state == configured`` AND ``query_suite == default``. Passes silently when scanning is off (SCM-003 owns that case) or when the suite is already ``extended``.

**Known false-positive modes**

- Teams that route code-scanning via a hand-authored CodeQL workflow rather than default setup will see SCM-045 pass by virtue of ``state != configured``; verify the workflow pins the extended suite. Some repos intentionally keep the default suite to bound CI minutes; suppress per repo with a rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

In ``Settings → Code security → Code scanning → Default setup``, switch ``Query suite`` from ``Default`` to ``Extended``. The extended suite adds CodeQL's ``security-and-quality`` pack, which catches maintainability and reliability issues that often co-occur with security findings (e.g. dead-code paths that hide an unauthenticated branch). Teams that ship a hand-authored CodeQL workflow can pin ``queries: security-extended`` in ``.github/codeql/codeql-config.yml`` for the same effect.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## SCM-046: Default code scanning has no periodic scan schedule { #scm-046 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Reads ``schedule`` from the default code-scanning setup endpoint. Fires (LOW) when ``state == configured`` AND schedule is ``None`` / ``"none"`` / missing, flagging the missing *periodic* re-scan. Push/PR scans still run, so this is a stale-branch coverage gap, not an absence of scanning. Passes silently when scanning is off entirely (SCM-003) or when a schedule is set.

**Known false-positive modes**

- Repos that route scanning via a hand-authored workflow (which carries its own schedule) may keep default setup configured but unscheduled intentionally. Suppress per repo with a rationale that names the workflow file.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``schedule`` to ``weekly`` on the default code-scanning setup (``Settings → Code security → Code scanning → Default setup → Edit configuration``). Push and pull-request scans already run without it, so this only adds the periodic re-scan that catches newly-detectable issues in code that isn't currently being pushed (stale branches, a quiet default branch). It does not gate merges; SCM-003 covers whether scanning exists at all.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-047: Repo language excluded from default code-scanning coverage { #scm-047 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-V-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Cross-references the linguist ``languages`` endpoint against the default-setup ``languages`` slot. Fires when a CodeQL-supported language present at ≥5% of repo bytes is missing from the scanning set. Passes silently when default scanning isn't configured (SCM-003 / SCM-046 own those cases) or when the languages endpoint is unavailable.

**Known false-positive modes**

- Monorepos may intentionally exclude legacy subdirectories from CodeQL analysis (e.g. a vendored fork). Suppress per repo with a rationale that names the excluded path; the default-setup language toggle is repo-wide, so a per-path exclusion requires a hand-authored workflow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Open the default code-scanning setup configuration (``Settings → Code security → Code scanning → Default setup → Edit configuration``) and add the missing languages to the analyzed set. If a language isn't CodeQL-supported (e.g. Shell, Lua), set up a third-party SAST workflow that uploads SARIF for that subset — default setup's auto-detect doesn't cover every language.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-048: Org codespace secret scoped to all repos { #scm-048 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``GET /orgs/{owner}/codespaces/secrets`` and flags every secret whose ``visibility`` field is ``"all"``. Requires ``admin:org`` scope on the token; without it GitHub returns 404 and the rule passes silently with an unavailability note.

Secrets with ``visibility: "private"`` (all private repos) or ``visibility: "selected"`` (named repo list) are not flagged. The ``private`` tier is a middle ground some orgs accept; ``selected`` is the tightest scope GitHub offers.

**Known false-positive modes**

- Organizations that genuinely need a secret in every repo (rare — examples include a shared telemetry token or an internal-CA certificate) should suppress with a rationale naming the secret and confirming the blast radius is accepted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope each org-level codespace secret to only the repos that need it: Organization Settings > Codespaces > Secrets > edit the secret > change Visibility from 'All repositories' to 'Selected repositories' and pick the specific repos. A secret visible to every repo in the org means any developer who opens a codespace in any repo (including forks of public repos, if codespaces are enabled for those) can read the value via ``${{ secrets.NAME }}`` or the ``CODESPACE_*`` environment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-049: Classic PAT used where a fine-grained token suffices { #scm-049 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Inspects the prefix of the ``$GITHUB_TOKEN`` (or ``--scm-token``) used for the SCM scan. ``ghp_`` indicates a classic PAT; ``github_pat_`` indicates a fine-grained PAT. Classic tokens carry org-wide scope and cannot be restricted to individual repos, which violates the principle of least privilege.

The rule passes silently when no token is provided or when the token is a GitHub App installation token (``ghs_`` / ``ghr_``), which already carries scoped permissions.

**Known false-positive modes**

- Some organizations have not yet adopted fine-grained PATs because of feature-parity gaps (e.g., some GraphQL endpoints require classic tokens). Suppress with a rationale documenting the specific API gap.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the classic personal access token (``ghp_`` prefix) with a fine-grained PAT (``github_pat_`` prefix). Fine-grained tokens restrict scope to named repos, carry per-permission grants, support expiration policies, and have a distinct audit-log shape. Classic PATs implicitly carry org-wide scope for every granted permission and cannot be restricted to individual repos.

Generate a fine-grained token at ``github.com/settings/personal-access-tokens/new`` and select only the repos and permissions the scanner needs (typically ``repo`` read + ``admin:org`` read for SCM posture scans).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-050: GitLab push rules do not block secret-shaped commits { #scm-050 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Reads ``repo_meta._gitlab_push_rule.prevent_secrets`` (populated from ``GET /projects/:id/push_rule``) and fires when the field is False or missing. The push-rule endpoint requires GitLab Premium / Ultimate; on Free the endpoint returns ``404`` and the rule passes silently with an unavailability note (the operator sees the deliberate skip rather than a silent absence). The same endpoint also surfaces ``commit_committer_check`` (SCM-051) and ``reject_unsigned_commits`` (already consumed by SCM-006), so the fetcher only issues one request to populate the whole push-rule slot.

**Known false-positive modes**

- GitLab Self-Managed deployments running CE (community edition, no Premium license) don't expose push rules at all; this rule passes silently on those snapshots. Suppress per-repo for known-CE installations to avoid the cosmetic skip note polluting the report.

**Seen in the wild**

- Long-running pattern of AWS / GCP credentials accidentally committed to GitLab repos and only caught by retroactive secret-scanning hours / days later; the GitHub equivalent (secret scanning + push protection, SCM-015) blocks the same class of commit at push time. Public examples: https://about.gitlab.com/blog/2023/04/20/gitlab-secret-detection/

<div class="pg-rule__rec" markdown>

**Recommended action**

On the project Settings -> Repository -> Push Rules panel, enable ``Prevent committing secrets to Git``. The setting maps to the API field ``prevent_secrets: true`` on ``PUT /projects/:id/push_rule`` and rejects any commit whose added lines match GitLab's bundled secret-pattern catalog (``aws_secret_key``, ``gcp_credentials.json``, ``id_rsa``, ``id_dsa``, ``server.crt``, ``database.yml`` with literal credentials). Pair with ``file_name_regex`` to block credential-shaped filenames (``\.env$``, ``\.npmrc$``, ``\.pypirc$``). Without ``prevent_secrets``, the platform accepts a commit that adds ``AKIA[A-Z0-9]{16}`` literals into the repo, leaving cleanup to retroactive secret-scanning + revocation. The push-rule guard is the shift-left equivalent: server-side rejection at ``git push`` time, before the bad commit ever lands.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-051: GitLab push rules do not enforce committer-email check { #scm-051 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``repo_meta._gitlab_push_rule.commit_committer_check`` and fires when False or missing. Endpoint is GitLab Premium / Ultimate; passes silently on CE / Free with a skip note. The committer-check guard is independent of signed commits: an unsigned commit with a verified committer email passes here but is caught by SCM-006; a signed commit with a spoofed committer email passes SCM-006 but is caught here. Both controls together produce the same posture GitHub achieves via vigilant mode + required signed commits.

**Known false-positive modes**

- GitLab CE / self-managed Free installations don't expose push rules; this rule passes silently on those snapshots. Mirror infrastructure repos that intentionally permit unverified committer emails (cross-org mirrors, third-party import flows) may also legitimately leave this off; suppress per-repo with a rationale.

**Seen in the wild**

- Maintainer-account compromise scenarios where the attacker pushes commits attributed to a different trusted contributor by setting ``committer.email``; without the check the platform accepts the push as-is, and the audit trail shows the wrong author until someone notices the missing verification badge.

<div class="pg-rule__rec" markdown>

**Recommended action**

On the project Settings -> Repository -> Push Rules panel, enable ``Reject unverified users`` (API field ``commit_committer_check: true``). The check rejects any push whose committer email doesn't match a verified address on the pusher's GitLab account, blocking the common spoofing pattern where a stolen credential pushes commits attributed to a different maintainer. Pair with ``reject_unsigned_commits`` (see SCM-006) for defense-in-depth: signed commits bind to a maintained key, committer-check binds to a verified email.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SCM-052: GitLab merge requests can land with unresolved discussions { #scm-052 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-1023</span>
</div>

Reads ``repo_meta._gitlab_project.only_allow_merge_if_all_discussions_are_resolved`` and fires when the field is False or missing. The flag is exposed on the standard ``GET /projects/:id`` endpoint, so this rule needs no extra API call beyond what the GitLab hydrator already issues.

**Known false-positive modes**

- Projects that gate merge entirely on approvals + status checks (a separate, equally valid posture) may deliberately leave discussion-resolution off so that informal threads don't block deploys. Suppress per-repo when the merge gate is well-covered by other rules.

**Seen in the wild**

- Common review-bypass pattern: a reviewer asks for a secret to be rotated or a regex to be tightened, the author replies inline but doesn't change the code, and the MR is merged before the discussion is closed. Without ``only_allow_merge_if_all_discussions_are_resolved``, the platform doesn't enforce that the unresolved feedback is addressed.

<div class="pg-rule__rec" markdown>

**Recommended action**

On the project Settings -> General -> Merge requests panel, enable ``All threads must be resolved`` (API field ``only_allow_merge_if_all_discussions_are_resolved: true`` on ``PUT /projects/:id``). The setting blocks merge until every code-review thread is marked resolved, closing the gap where a reviewer raises a security concern in a discussion but the merge happens before the author addresses it. The GitHub analog is ``required_conversation_resolution`` (covered by SCM-013 on the GitHub side).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-053: GitLab merge requests allow the author to approve their own MR { #scm-053 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``merge_requests_author_approval`` from the project approvals endpoint (``GET /projects/:id/approvals``, stashed as ``repo_meta._gitlab_approvals``) and fires when True (the unsafe value). The field is not on the ``GET /projects/:id`` payload. GitLab inverts the field semantics: ``true`` means author approval is permitted, ``false`` means it's disabled. The rule normalizes this so a passing finding reflects the safe posture regardless of the API's boolean polarity. Together with SCM-002 (required approval count >= 1) this catches the full self-merge bypass; either rule alone is insufficient.

**Known false-positive modes**

- Single-maintainer projects (personal repos, small experimental projects) by design have no reviewer pool, so author approval is the only signal available. Suppress per-repo for those cases with a rationale naming the project's single-author posture.

**Seen in the wild**

- Classic self-merge bypass: an attacker with a single maintainer-account compromise pushes a MR, approves it themselves, and merges. With author-approval disabled the approve-button click is rejected at the API level and a second reviewer is forced.

<div class="pg-rule__rec" markdown>

**Recommended action**

On the project Settings -> Merge requests -> Approvals panel, disable ``Allow author of merge request to approve their own merge request``. The API surfaces this as ``merge_requests_author_approval: false`` on ``POST /projects/:id/approvals`` (the inverted boolean: ``false`` *disables* author approval, which is the safe posture). Combined with ``approvals_before_merge >= 1`` (already audited by SCM-002 on the universal-rules side), the approval gate becomes meaningful: the author can't self-merge by clicking Approve and bypassing review.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-054: Bitbucket private repo allows public forks { #scm-054 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``repo_meta._bitbucket_repo.fork_policy`` and fires when the repo is private (``is_private: true``) and ``fork_policy`` is ``allow_forks`` (the permissive value). Public repos are not flagged: a public source repo is already visible, so a public fork doesn't increase the disclosure surface. The Bitbucket Cloud API exposes ``fork_policy`` directly on the repo object, so no extra fetch is needed beyond what the hydrator already issues.

**Known false-positive modes**

- Repos that are explicitly meant as upstream templates for community contribution may have been set to ``allow_forks`` on purpose. The right pattern in that case is to either make the source public (so ``allow_forks`` is a no-op for confidentiality) or switch to ``no_public_forks`` (still allows community forks but keeps them inside the workspace's privacy boundary). Suppress per-repo for known-public templates.

**Seen in the wild**

- Bitbucket workspace policy gap that surfaces in audits of multi-tenant SaaS engineering orgs: a private monorepo with ``allow_forks`` lets a contractor fork the entire commit history into their personal workspace, where the source plus full git log is now visible to anyone with the fork URL. Detection requires auditing fork lists per-repo, which most orgs never do.

<div class="pg-rule__rec" markdown>

**Recommended action**

On the repo Settings -> Repository details panel, set ``Forking`` to either ``Disabled`` or ``Restrict to private forks``. The API field is ``fork_policy`` with three values: ``allow_forks`` (permissive, the failure case this rule catches), ``no_public_forks`` (forks allowed but they inherit the parent's private visibility), and ``no_forks`` (forks blocked entirely). On a private repo, ``allow_forks`` means any workspace member can fork the repo into a public personal workspace, which silently makes the source visible to the entire internet. The fork retains the parent's commit history including any secrets the source repo's secret-scanning policy hasn't yet rotated.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SCM-055: Bitbucket default branch has no write-side restriction kinds { #scm-055 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads the branch-restrictions list from ``GET /2.0/repositories/{ws}/{repo}/branch-restrictions`` (populated by the universal SCM-001 path) and inspects the restrictions on the default branch. Fires when no restriction of kind ``push`` / ``force`` / ``delete`` is present, even if other merge-side restrictions exist. SCM-001 ensures *some* restriction is present; SCM-055 ensures the right *kind* is present.

Reads the raw payload via ``repo_meta._bitbucket_repo`` for the default-branch name and the universal-rules ``default_branch_protection`` slot for the presence signal.

**Known false-positive modes**

- Some workspaces gate writes entirely via workspace-level user-group permissions rather than per-branch restrictions; in that case the branch-restrictions list is intentionally empty of write-side kinds and the control is enforced one layer up. Suppress per-repo with a rationale naming the workspace-level enforcement.

**Seen in the wild**

- Bitbucket admin-push bypass: a repo with ``require_approvals_to_merge=2`` and ``require_passing_builds_to_merge`` but no ``push``-kind restriction. A repo admin with stolen credentials pushes a malicious commit directly to main, bypassing both merge-side gates because the gates only apply to PRs.

<div class="pg-rule__rec" markdown>

**Recommended action**

On the repo Settings -> Branch restrictions panel, add at least one write-side restriction (``Prevent push`` / ``Prevent force push`` / ``Prevent deletion``) on the default branch in addition to any merge-side checks (``Require approvals``, ``Require passing builds``). Without a ``push``-kind restriction, branch admins can still push directly to the default branch, bypassing the PR-and-approve flow that the merge-side checks gate. The common misconfiguration is to add ``Require N approvals to merge`` but no ``Prevent push``, which means PRs are well-gated but direct pushes are unrestricted.

</div>

</div>

---

## Adding a new SCM posture (GitHub) check

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
