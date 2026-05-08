# Attack Chains

A single finding rarely captures the full risk of a CI/CD misconfiguration.
A `pull_request_target` trigger is bad on its own; long-lived AWS credentials
are bad on their own; but the *combination* — on the same workflow — is
exactly how the PyTorch supply-chain compromise worked. Pipeline-Check's
**attack chain** engine correlates findings into those multi-step
narratives and emits one higher-order result per matched chain, mapped to
[MITRE ATT&CK](https://attack.mitre.org/) techniques.

Chains are **additive**. They never replace a finding — they sit on top of
the finding set and highlight the combinations that map to real-world
attack paths. Fix any one leg and the chain breaks.

## Registered chains

| ID | Title | Severity | Providers | Triggering checks |
|----|-------|----------|-----------|-------------------|
| [`AC-001`](#ac-001) | Fork-PR Credential Theft (`pull_request_target`) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-002`](providers/github.md#gha-002) + [`GHA-005`](providers/github.md#gha-005) |
| [`AC-002`](#ac-002) | Script Injection to Unprotected Deploy | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-003`](providers/github.md#gha-003) + [`GHA-014`](providers/github.md#gha-014) |
| [`AC-003`](#ac-003) | Unpinned Action to Credential Exfiltration | <span class="pg-sev pg-sev--high">HIGH</span> | github | [`GHA-001`](providers/github.md#gha-001) + [`GHA-005`](providers/github.md#gha-005) |
| [`AC-004`](#ac-004) | Self-Hosted Runner Persistent Foothold | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-002`](providers/github.md#gha-002) + [`GHA-012`](providers/github.md#gha-012) |
| [`AC-005`](#ac-005) | Unsigned Artifact to Production | <span class="pg-sev pg-sev--high">HIGH</span> | (cross-provider) | build-side `*-006` / [`SIGN-001`](providers/aws.md) + deploy-gate `*-014` / [`GCB-009`](providers/cloudbuild.md#gcb-009) / [`CP-001`](providers/aws.md) / [`CP-005`](providers/aws.md) |
| [`AC-006`](#ac-006) | Cache Poisoning via Untrusted Trigger | <span class="pg-sev pg-sev--high">HIGH</span> | github | [`GHA-002`](providers/github.md#gha-002) + [`GHA-011`](providers/github.md#gha-011) |
| [`AC-007`](#ac-007) | IAM Privilege Escalation via CodeBuild | <span class="pg-sev pg-sev--critical">CRITICAL</span> | aws / terraform / cloudformation | [`CB-002`](providers/aws.md) + ([`IAM-002`](providers/aws.md) or [`IAM-004`](providers/aws.md)) |
| [`AC-008`](#ac-008) | Dependency Confusion Window | <span class="pg-sev pg-sev--high">HIGH</span> | github | [`GHA-021`](providers/github.md#gha-021) + [`GHA-029`](providers/github.md#gha-029) |
| [`AC-009`](#ac-009) | Supply Chain Repo Poisoning | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-001`](providers/github.md#gha-001) + [`GHA-002`](providers/github.md#gha-002) + [`GHA-008`](providers/github.md#gha-008) |
| [`AC-010`](#ac-010) | Self-Hosted Runner Environment Exfiltration | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-012`](providers/github.md#gha-012) + ([`GHA-016`](providers/github.md#gha-016) or [`GHA-019`](providers/github.md#gha-019)) |
| [`AC-011`](#ac-011) | Kubernetes Cluster Takeover via hostPath + cluster-admin | <span class="pg-sev pg-sev--critical">CRITICAL</span> | kubernetes | [`K8S-013`](providers/kubernetes.md#k8s-013) + [`K8S-020`](providers/kubernetes.md#k8s-020) |

Run `pipeline_check --list-chains` to see the current set at any time.
Run `pipeline_check --explain-chain AC-001` for the full reference
(summary, narrative, MITRE techniques, kill-chain phase, references,
recommendation).

## How chains surface in output

- **Terminal** — a panel per chain after the findings table, with a
  colored border matching the chain's severity and the full narrative
  inline.
- **JSON** — `chains` top-level array carrying every field plus
  `triggering_findings: [{check_id, resource}, …]`. Omitted (not empty)
  when the caller passed `--no-chains`, so consumers can distinguish
  "nothing matched" from "not asked for".
- **SARIF** — one rule and one result per chain, tagged `attack-chain`
  plus `mitre/T…` for each technique. GitHub Code Scanning surfaces
  them as top-level alerts.
- **HTML** — an Attack Chains section immediately after the score
  card. Each chain is a bordered card with severity, confidence,
  narrative, triggering checks, MITRE techniques, and references.
- **Markdown** — an Attack Chains H2 between the summary line and the
  Failures table, so a PR comment reader sees the highest-signal
  artifact first.

## Gating CI on chains

```bash
# Fail the gate only on named chains (the team has explicitly
# opted in to blocking these patterns).
pipeline_check --fail-on-chain AC-001 --fail-on-chain AC-007

# Blanket guard: fail if any chain matched at all.
pipeline_check --fail-on-any-chain
```

Chain gates **bypass baseline and ignore-file filtering** — a correlated
attack path is intrinsically a new finding even when the constituent
legs were baselined separately. An `AC-001` match that surfaces after
an OIDC migration partial-rollout would otherwise hide behind two
green baseline suppressions.

## Disabling chain evaluation

```bash
pipeline_check --no-chains
```

Drops the chain correlation pass entirely. The `chains` key is omitted
from the JSON payload. Useful when a downstream consumer doesn't
understand the field, or to shave a few milliseconds off a CI hot
path (chain evaluation is O(findings × rules), cheap in practice).

## Confidence inheritance

A chain is only as trustworthy as its weakest leg. `Chain.confidence`
is set to the minimum confidence among the triggering findings — if
one leg comes from a LOW-confidence blob heuristic, the chain is
reported at LOW confidence even when every other leg is HIGH. The
`--min-confidence` filter applies the same way to chains as to
findings.

## Adding a new chain

Chains are plugin-discovered from `pipeline_check/core/chains/rules/`.
Drop a module named `ac<NNN>_<slug>.py` exporting a `RULE` of type
`ChainRule` and a `match(findings) -> list[Chain]` function. The
engine auto-registers it at import time. See the existing
`ac001_fork_pr_credential_theft.py` for the canonical shape — most
chains only need `group_by_resource(findings, [...])` plus a narrative
template.

<!-- chain-catalog:start -->

## Chain catalog

Click any chain in the [registered chains](#registered-chains) table above to jump to its detail card below. Each card carries the chain's severity, MITRE ATT&CK techniques, kill-chain phase, summary prose, references, and the remediation that breaks the chain.

<div class="pg-rule pg-rule--critical" markdown>

### AC-001 — Fork-PR Credential Theft (pull_request_target) { #ac-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A pull_request_target workflow checks out PR-head code while exposing long-lived AWS credentials. A fork-PR opener can run arbitrary code in the privileged context and exfiltrate the credentials before the PR is even reviewed.

**References**

- <https://securitylab.github.com/research/github-actions-preventing-pwn-requests/>
- <https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break the chain by either (a) switching to `pull_request` (no write-scope token), or (b) replacing static AWS keys with OIDC `role-to-assume` scoped to the workflow.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-002 — Script Injection to Unprotected Deploy { #ac-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1059.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1190</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1648</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> impact</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow interpolates untrusted GitHub event data into a shell command (script-injection) and the same workflow deploys without an environment-gated approval. An attacker with PR/issue access can hijack the deploy.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution-PPE>
- <https://github.blog/security/application-security/four-tips-to-keep-your-github-actions-workflows-secure/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pipe untrusted input through an env-var (one-shot quoting) and add `environment: production` with required reviewers to the deploy job. Either fix alone narrows the chain.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-003 — Unpinned Action to Credential Exfiltration { #ac-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="kill-chain phase">supply-chain -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow consumes third-party actions by mutable tag (`@v1`, `@main`) AND holds long-lived cloud credentials. An action maintainer (or an attacker who compromises the action repo) can swap in malicious code on the next run and exfiltrate the credentials.

**References**

- <https://blog.gitguardian.com/github-actions-security-cheat-sheet/>
- <https://github.com/tj-actions/changed-files>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every third-party action to a 40-char SHA. Combined with OIDC short-lived credentials this chain becomes infeasible: a compromised action no longer has a valid long-lived secret to steal.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-004 — Self-Hosted Runner Persistent Foothold { #ac-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1543</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1554</span> <span class="pg-tag" title="kill-chain phase">initial-access -> persistence -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A self-hosted runner is configured non-ephemerally AND the same workflow accepts a fork-trigger that can run untrusted code. The runner OS persists between jobs, so malicious code from a fork PR can plant a long-lived backdoor that intercepts the next privileged build.

**References**

- <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>
- <https://www.praetorian.com/blog/self-hosted-github-runners-are-backdoors/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Use ephemeral runners (one job, then destroy the host). If ephemeral isn't possible, restrict the workflow trigger to first-party events only — `pull_request` from forks must land on GitHub-hosted runners exclusively.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-005 — Unsigned Artifact to Production { #ac-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1554</span> <span class="pg-tag" title="kill-chain phase">supply-chain -> defense-evasion -> impact</span>
</div>

Artifacts are produced without signing or provenance AND the deployment path to production has no manual approval gate. A build-time compromise (compromised dependency, malicious action, runner takeover) reaches prod uninspected and post-incident attribution is impossible.

**References**

- <https://slsa.dev/spec/v1.0/levels>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility>

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step (`cosign sign`, `gh attestation`) or SLSA provenance generation, AND require manual approval before production deploys (CodePipeline approval action, GHA environment with required reviewers).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-006 — Cache Poisoning via Untrusted Trigger { #ac-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1554</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="kill-chain phase">initial-access -> persistence -> impact</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow accepts an untrusted trigger (fork PR, issue_comment) AND uses an attacker-influenceable cache key. The attacker plants a poisoned cache entry that the next privileged build (push to main, scheduled deploy) restores and trusts.

**References**

- <https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/>
- <https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#restrictions-for-accessing-a-cache>

<div class="pg-rule__rec" markdown>

**Recommended action**

Lock cache keys to verifiable inputs (lockfile hashes, not PR-controlled paths). Restrict caches to push events only and scope by ref. Either fix breaks the chain.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-007 — IAM Privilege Escalation via CodeBuild { #ac-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1548.005</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.001</span> <span class="pg-tag" title="kill-chain phase">execution -> privilege-escalation -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">aws</span> <span class="pg-tag pg-tag--owasp">terraform</span> <span class="pg-tag pg-tag--owasp">cloudformation</span>
</div>

A CodeBuild project runs in privileged mode AND its service role grants wildcard IAM actions or unconstrained PassRole. Anyone who can land a buildspec change (or a poisoned dependency the build pulls) can assume a higher-privileged role and pivot across the account.

**References**

- <https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/>
- <https://docs.aws.amazon.com/codebuild/latest/userguide/security-iam.html>

<div class="pg-rule__rec" markdown>

**Recommended action**

Strip wildcard actions and unconstrained PassRole from the CodeBuild service role; pin PassRole to specific role ARNs with a build-tag condition. Disable privileged mode unless the build genuinely requires Docker-in-Docker.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-008 — Dependency Confusion Window { #ac-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="kill-chain phase">supply-chain -> execution</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow installs packages without a lockfile AND without integrity verification. On every run the dependency resolver picks the highest-version match across configured registries — ideal conditions for a dependency-confusion / typosquatting attack to land in the build.

**References**

- <https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>

<div class="pg-rule__rec" markdown>

**Recommended action**

Use lockfile-enforcing install commands (`npm ci`, `pip install -r requirements.txt --require-hashes`, `yarn install --frozen-lockfile`). Pin the registry to a private one and disable upstream fall-through.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-009 — Supply Chain Repo Poisoning { #ac-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow uses unpinned third-party actions (GHA-001), interpolates untrusted PR context into a shell ``run:`` block (GHA-002), and carries literal secrets in the YAML (GHA-008). Any one of those is exploitable; the combination gives a fork-PR attacker two independent code-execution paths to the same plaintext credentials.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>
- <https://securitylab.github.com/research/github-actions-untrusted-input/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every third-party action to a commit SHA (not a tag). Move secrets out of the YAML and into the GitHub Secrets store, referenced via ``${{ secrets.NAME }}``. Replace direct interpolation of PR-controlled context (`event.*`, `pull_request.*`) into shell with environment-variable indirection.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-010 — Self-Hosted Runner Environment Exfiltration { #ac-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="kill-chain phase">execution -> persistence -> credential-access</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A self-hosted runner without ephemeral isolation (GHA-012) executes a workflow that either pipes a remote script into a shell (GHA-016) or persists the GitHub token across jobs (GHA-019). Both legs give an attacker a route to plant persistence on the runner; the runner's filesystem then harvests every secret subsequent workflows expose.

**References**

- <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>
- <https://www.legitsecurity.com/blog/github-self-hosted-runners-vulnerabilities>

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure self-hosted runners as ephemeral (one job per VM, recycled afterward). For each job, replace remote-script-into-shell idioms (``curl ... | bash``) with a verified, version-pinned download step, and set ``persist-credentials: false`` on every checkout.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-011 — Kubernetes Cluster Takeover via hostPath + cluster-admin { #ac-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1611</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="kill-chain phase">initial-access -> privilege-escalation -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">kubernetes</span>
</div>

A workload mounts a hostPath volume (K8S-013) AND the cluster carries a ClusterRoleBinding granting cluster-admin (K8S-020). Together those two settings give an attacker who lands code in any pod on a poisoned node both an escape to the host filesystem and the API privileges needed to pivot the entire cluster — read every Secret, deploy privileged workloads across all nodes, impersonate any service account.

**References**

- <https://kubernetes.io/docs/concepts/storage/volumes/#hostpath>
- <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- <https://www.cncf.io/blog/2024/04/29/the-dangerous-cluster-admin/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace hostPath volumes with a CSI driver scoped to the specific subtree the workload needs, or use ConfigMap / downwardAPI volumes for non-storage cases. Audit ClusterRoleBindings: cluster-admin should be reserved for a narrow human-operator group with break-glass access — never bound to a ServiceAccount or a broad ``Group``. Even with hostPath in place, removing the cluster-admin grant breaks the API-pivot leg of this chain.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-012 — Reusable Workflow Secret Exfiltration { #ac-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow calls a reusable workflow whose ``uses:`` ref is mutable (tag / branch) AND passes ``secrets: inherit``. The owner of the upstream repo can repoint the tag to malicious code; the next caller-side run hands every caller secret to that code under cover of normal reusable-workflow plumbing.

**References**

- <https://docs.github.com/en/actions/sharing-automations/reusing-workflows#using-inputs-and-secrets-in-a-reusable-workflow>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3-Dependency-Chain-Abuse>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg of the chain. (a) Replace the mutable ref (``@v2`` / ``@main``) with a 40-char commit SHA so an upstream tag move can't repoint to attacker code. (b) Replace ``secrets: inherit`` with an explicit allowlist (``secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``) so a compromised callee can't reach unrelated credentials. Doing (a) closes the supply-chain leg; (b) limits blast radius even if (a) is somehow bypassed.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-013 — Caller-Controlled Runner with Token Persistence { #ac-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1133</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow's ``runs-on:`` is computed from an attacker-controllable expression (GHA-036) AND a step in the same workflow writes ``GITHUB_TOKEN`` to persistent storage (GHA-019). The caller (or PR sender) picks which runner the workflow lands on; the workflow then drops its short-lived token onto that runner's filesystem; whoever owns the picked runner harvests the token and acts as the workflow inside the repo.

**References**

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg of the chain. (a) Hard-code ``runs-on:`` or validate the input against an allowlist of known-good labels before the job runs, so the caller can't pick an attacker-controlled runner. (b) Stop writing ``GITHUB_TOKEN`` to disk — use it inline via ``${{ secrets.GITHUB_TOKEN }}`` in the step that needs it. Doing (a) closes the targeting leg; (b) limits blast radius even if (a) is somehow bypassed because the token no longer outlives the step that consumes it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-014 — Caller-Controlled Runner with Token Persistence (GitLab) { #ac-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1133</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">gitlab</span>
</div>

A pipeline's ``tags:`` is computed from an attacker-controllable CI variable (GL-032) AND a script line in the same job writes ``CI_JOB_TOKEN`` (or another CI-managed credential) to persistent storage (GL-020). The pipeline trigger picks which tagged runner the job lands on; the job then drops its short-lived token onto that runner's filesystem; whoever owns the picked runner harvests the token and acts as the pipeline against the GitLab API.

**References**

- <https://docs.gitlab.com/ee/ci/runners/configure_runners.html#runner-security>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg of the chain. (a) Hard-code ``tags:`` to a specific runner-tag list, or validate the value against an allowlist in a ``rules:`` guard before the job runs, so the trigger can't pick an attacker-controlled runner. (b) Stop writing ``CI_JOB_TOKEN`` (or other CI-managed credentials) to disk — use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes. Doing (a) closes the targeting leg; (b) limits blast radius even if (a) is somehow bypassed because the token no longer outlives the step that consumes it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-015 — Helm chart-supply-chain takeover via legacy + unlocked + plaintext { #ac-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1557</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> persistence</span> <span class="pg-tag pg-tag--owasp">helm</span>
</div>

A Helm chart simultaneously declares the legacy v1 schema (HELM-001), ships dependencies without ``Chart.lock`` digest verification (HELM-002), and lists at least one dependency on a non-HTTPS repository (HELM-003). An attacker on the path to ``helm dependency build`` substitutes the dependency tarball; nothing in the chart's metadata can detect or reject the swap, so the substituted code runs in every cluster the chart deploys to.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>
- <https://helm.sh/docs/topics/charts/#chart-dependencies>
- <https://helm.sh/docs/helm/helm_dependency_build/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump every chart to ``apiVersion: v2`` so the in-tree ``Chart.lock`` mechanism is available. Re-run ``helm dependency update`` to populate per-dependency ``sha256:`` digests in the lock and commit it alongside ``Chart.yaml``. Switch each ``dependencies[].repository`` to ``https://``, ``oci://``, or a ``file://`` sibling — Helm 3.8+ pulls OCI-hosted charts over HTTPS by default and is the recommended distribution shape. Removing any *one* of these three legs breaks this chain (the lock catches a swap on the next update; HTTPS catches it before the tarball lands; v2 makes the lock possible in the first place).

</div>

</div>


<!-- chain-catalog:end -->
