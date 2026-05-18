# Attack Chains

A single finding rarely captures the full risk of a CI/CD misconfiguration.
A `pull_request_target` trigger is bad on its own; long-lived AWS credentials
are bad on their own; but the *combination*, on the same workflow, is
exactly how the PyTorch supply-chain compromise worked. Pipeline-Check's
**attack chain** engine correlates findings into those multi-step
narratives and emits one higher-order result per matched chain, mapped to
[MITRE ATT&CK](https://attack.mitre.org/) techniques.

Chains are **additive**. They never replace a finding. They sit on top of
the finding set and highlight the combinations that map to real-world
attack paths. Fix any one leg and the chain breaks.

## Registered chains

Two families:

- **`AC-NNN`** chains are single-provider correlations. They fire on
  a normal `--pipeline <name>` scan.
- **`XPC-NNN`** chains are cross-provider correlations. They fire
  only when the chain engine sees findings from multiple providers
  in the same scan, which happens when you pass
  `--pipelines github,oci` (plural, comma-separated) instead of
  single-valued `--pipeline`. A single-provider run never sees both
  legs, so the `XPC-*` rules stay quiet there.

Run `pipeline_check --list-chains` to see the current set at any
time. Run `pipeline_check --explain-chain AC-001` for the full
reference (summary, narrative, MITRE techniques, kill-chain phase,
references, recommendation).

### Single-provider chains (`AC-NNN`)

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
| [`AC-012`](#ac-012) | Reusable Workflow Secret Exfiltration | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-025`](providers/github.md#gha-025) + [`GHA-034`](providers/github.md#gha-034) |
| [`AC-013`](#ac-013) | Caller-Controlled Runner with Token Persistence | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-036`](providers/github.md#gha-036) + [`GHA-019`](providers/github.md#gha-019) |
| [`AC-014`](#ac-014) | Caller-Controlled Runner with Token Persistence (GitLab) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | gitlab | [`GL-032`](providers/gitlab.md#gl-032) + [`GL-020`](providers/gitlab.md#gl-020) |
| [`AC-015`](#ac-015) | Helm chart-supply-chain takeover via legacy + unlocked + plaintext | <span class="pg-sev pg-sev--critical">CRITICAL</span> | helm | [`HELM-001`](providers/helm.md#helm-001) + [`HELM-002`](providers/helm.md#helm-002) + [`HELM-003`](providers/helm.md#helm-003) |
| [`AC-016`](#ac-016) | OIDC role drift: ungated GitHub trust meets wildcard AWS authority | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github / aws | [`GHA-030`](providers/github.md#gha-030) + [`IAM-002`](providers/aws.md) |
| [`AC-017`](#ac-017) | Build cache poisoning that lands on a mutable ECR tag | <span class="pg-sev pg-sev--high">HIGH</span> | github / aws | [`GHA-011`](providers/github.md#gha-011) + [`ECR-002`](providers/aws.md) |
| [`AC-018`](#ac-018) | Unpinned action lands on deploy job with no environment gate | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github | [`GHA-001`](providers/github.md#gha-001) + [`GHA-014`](providers/github.md#gha-014) |
| [`AC-019`](#ac-019) | Lambda env-secret meets a CI/CD role with PassRole * | <span class="pg-sev pg-sev--critical">CRITICAL</span> | aws | [`LMB-003`](providers/aws.md) + [`IAM-004`](providers/aws.md) |
| [`AC-020`](#ac-020) | Tekton hostPath build workload meets cluster-admin RBAC | <span class="pg-sev pg-sev--critical">CRITICAL</span> | tekton / kubernetes | [`TKN-004`](providers/tekton.md#tkn-004) + [`K8S-020`](providers/kubernetes.md#k8s-020) |
| [`AC-021`](#ac-021) | Argo default-SA workflow lands on a default-SA RoleBinding | <span class="pg-sev pg-sev--high">HIGH</span> | argo / kubernetes | [`ARGO-003`](providers/argo.md#argo-003) + [`K8S-029`](providers/kubernetes.md#k8s-029) |
| [`AC-022`](#ac-022) | GitLab script injection lands on deploy job with no manual gate | <span class="pg-sev pg-sev--critical">CRITICAL</span> | gitlab | [`GL-002`](providers/gitlab.md#gl-002) + [`GL-004`](providers/gitlab.md#gl-004) |
| [`AC-023`](#ac-023) | Tekton param injection lands in a privileged or root step | <span class="pg-sev pg-sev--critical">CRITICAL</span> | tekton | [`TKN-002`](providers/tekton.md#tkn-002) + [`TKN-003`](providers/tekton.md#tkn-003) |
| [`AC-024`](#ac-024) | OIDC trust drift lands on a mutable ECR tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | github / aws | [`GHA-030`](providers/github.md#gha-030) + [`ECR-002`](providers/aws.md) |
| [`AC-025`](#ac-025) | Argo param injection lands in a privileged or root step | <span class="pg-sev pg-sev--critical">CRITICAL</span> | argo | [`ARGO-002`](providers/argo.md#argo-002) + [`ARGO-005`](providers/argo.md#argo-005) |
| [`AC-026`](#ac-026) | Buildkite injection lands on auto-deploy step with no manual gate | <span class="pg-sev pg-sev--critical">CRITICAL</span> | buildkite | [`BK-003`](providers/buildkite.md#bk-003) + [`BK-007`](providers/buildkite.md#bk-007) |
| [`AC-027`](#ac-027) | Image bakes a credential file AND exposes a remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | dockerfile | [`DF-013`](providers/dockerfile.md#df-013) + [`DF-019`](providers/dockerfile.md#df-019) |

### Cross-provider chains (`XPC-NNN`)

These need `--pipelines <a>,<b>,…` (or auto-detect of two or more
providers at cwd) so the chain engine has findings from both legs in
one scan.

| ID | Title | Severity | Providers | Triggering checks |
|----|-------|----------|-----------|-------------------|
| [`XPC-001`](#xpc-001) | Deploy without verifiable provenance (workflow + image) | <span class="pg-sev pg-sev--high">HIGH</span> | github / oci | [`GHA-006`](providers/github.md#gha-006) + [`OCI-002`](providers/oci.md#oci-002) |
| [`XPC-002`](#xpc-002) | Tag mutability across pipeline + runtime (Dockerfile + K8s) | <span class="pg-sev pg-sev--high">HIGH</span> | dockerfile / kubernetes | [`DF-001`](providers/dockerfile.md#df-001) + [`K8S-001`](providers/kubernetes.md#k8s-001) |
| [`XPC-003`](#xpc-003) | Unverified Helm release flow (chart + image) | <span class="pg-sev pg-sev--high">HIGH</span> | helm / oci | [`HELM-002`](providers/helm.md#helm-002) + [`OCI-002`](providers/oci.md#oci-002) |
| [`XPC-004`](#xpc-004) | Token persistence on an unprotected default branch | <span class="pg-sev pg-sev--critical">CRITICAL</span> | scm / github | (`SCM-001` &or; `SCM-007`) + [`GHA-019`](providers/github.md#gha-019) |
| [`XPC-005`](#xpc-005) | End-to-end provenance gap: source unsigned, artifact unsigned | <span class="pg-sev pg-sev--high">HIGH</span> | scm / github | [`SCM-006`](providers/scm.md#scm-006) + [`GHA-006`](providers/github.md#gha-006) |
| [`XPC-006`](#xpc-006) | Unreviewed fork-PR privilege escalation | <span class="pg-sev pg-sev--critical">CRITICAL</span> | scm / github | [`SCM-002`](providers/scm.md#scm-002) + [`GHA-002`](providers/github.md#gha-002) |
| [`XPC-007`](#xpc-007) | Unpinned actions with no automated remediation | <span class="pg-sev pg-sev--high">HIGH</span> | scm / github | [`SCM-005`](providers/scm.md#scm-005) + [`GHA-001`](providers/github.md#gha-001) |
| [`XPC-008`](#xpc-008) | Unreviewed source ships a mutable runtime image | <span class="pg-sev pg-sev--high">HIGH</span> | scm / dockerfile | (`SCM-001` &or; `SCM-007`) + [`DF-001`](providers/dockerfile.md#df-001) |
| [`XPC-009`](#xpc-009) | Ingested CVE finding plus mutable runtime image reference | <span class="pg-sev pg-sev--high">HIGH</span> | ingest / dockerfile | `INGEST-trivy-*` / `INGEST-grype-*` / `INGEST-snyk-*` + [`DF-001`](providers/dockerfile.md#df-001) |

## How chains surface in output

- **Terminal**: a panel per chain after the findings table, with a
  colored border matching the chain's severity and the full narrative
  inline.
- **JSON**: `chains` top-level array carrying every field plus
  `triggering_findings: [{check_id, resource}, …]`. Omitted (not empty)
  when the caller passed `--no-chains`, so consumers can distinguish
  "nothing matched" from "not asked for".
- **SARIF**: one rule and one result per chain, tagged `attack-chain`
  plus `mitre/T…` for each technique. GitHub Code Scanning surfaces
  them as top-level alerts.
- **HTML**: an Attack Chains section immediately after the score
  card. Each chain is a bordered card with severity, confidence,
  narrative, triggering checks, MITRE techniques, and references.
- **Markdown**: an Attack Chains H2 between the summary line and the
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

Chain gates **bypass baseline and ignore-file filtering**, a correlated
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

## Reachability-aware chains

Most attack-chain detectors fire on co-occurrence: two trigger
findings on the same resource are taken as evidence that the
composite attack is possible. That answer is correct as a screening
signal but weaker than what's available: each finding knows the job
it fired in, and intersecting those job sets confirms whether the
two legs share an executable path or only happen to live in the same
file.

Chains that have opted in to the model expose two extra fields:

- `confirmed_reachable: bool` — `true` when the trigger findings'
  `job_anchors` intersect (or a `TAINT-001` / `TAINT-002` dataflow
  path bridges them). `false` is the default for chains that haven't
  been migrated yet.
- `reachability_note: str` — a short rationale, e.g.
  `"injection and ungated deploy share job `release`"`. Empty when
  the chain isn't confirmed reachable.

Confirmed-reachable chains are promoted to `HIGH` confidence
regardless of their constituent legs and rendered with a
`✓ Reachability confirmed` badge in the terminal / Markdown / HTML
outputs.

`AC-002` (script injection to unprotected deploy) is the first chain
migrated. Add `--chains-require-reachability` to drop unconfirmed
chains entirely, the strictest signal available:

```bash
pipeline_check -p github --chains-require-reachability \
    --fail-on-chain CRITICAL
```

## Confidence inheritance

A chain is only as trustworthy as its weakest leg. `Chain.confidence`
is set to the minimum confidence among the triggering findings, if
one leg comes from a LOW-confidence blob heuristic, the chain is
reported at LOW confidence even when every other leg is HIGH. The
`--min-confidence` filter applies the same way to chains as to
findings.

## Adding a new chain

Chains are plugin-discovered from `pipeline_check/core/chains/rules/`.
Drop a module named `ac<NNN>_<slug>.py` exporting a `RULE` of type
`ChainRule` and a `match(findings) -> list[Chain]` function. The
engine auto-registers it at import time. See the existing
`ac001_fork_pr_credential_theft.py` for the canonical shape, most
chains only need `group_by_resource(findings, [...])` plus a narrative
template.

<!-- chain-catalog:start -->

## Chain catalog

Click any chain in the [registered chains](#registered-chains) table above to jump to its detail card below. Each card carries the chain's severity, MITRE ATT&CK techniques, kill-chain phase, summary prose, references, and the remediation that breaks the chain.

<div class="pg-rule pg-rule--critical" markdown>

### AC-001: Fork-PR Credential Theft (pull_request_target) { #ac-001 }

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

### AC-002: Script Injection to Unprotected Deploy { #ac-002 }

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

### AC-003: Unpinned Action to Credential Exfiltration { #ac-003 }

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

### AC-004: Self-Hosted Runner Persistent Foothold { #ac-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1543</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1554</span> <span class="pg-tag" title="kill-chain phase">initial-access -> persistence -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A self-hosted runner is configured non-ephemerally AND the same workflow accepts a fork-trigger that can run untrusted code. The runner OS persists between jobs, so malicious code from a fork PR can plant a long-lived backdoor that intercepts the next privileged build.

**References**

- <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>
- <https://www.praetorian.com/blog/self-hosted-github-runners-are-backdoors/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Use ephemeral runners (one job, then destroy the host). If ephemeral isn't possible, restrict the workflow trigger to first-party events only, `pull_request` from forks must land on GitHub-hosted runners exclusively.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-005: Unsigned Artifact to Production { #ac-005 }

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

### AC-006: Cache Poisoning via Untrusted Trigger { #ac-006 }

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

### AC-007: IAM Privilege Escalation via CodeBuild { #ac-007 }

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

### AC-008: Dependency Confusion Window { #ac-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="kill-chain phase">supply-chain -> execution</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow installs packages without a lockfile AND without integrity verification. On every run the dependency resolver picks the highest-version match across configured registries, ideal conditions for a dependency-confusion / typosquatting attack to land in the build.

**References**

- <https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>

<div class="pg-rule__rec" markdown>

**Recommended action**

Use lockfile-enforcing install commands (`npm ci`, `pip install -r requirements.txt --require-hashes`, `yarn install --frozen-lockfile`). Pin the registry to a private one and disable upstream fall-through.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-009: Supply Chain Repo Poisoning { #ac-009 }

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

### AC-010: Self-Hosted Runner Environment Exfiltration { #ac-010 }

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

### AC-011: Kubernetes Cluster Takeover via hostPath + cluster-admin { #ac-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1611</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="kill-chain phase">initial-access -> privilege-escalation -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">kubernetes</span>
</div>

A workload mounts a hostPath volume (K8S-013) AND the cluster carries a ClusterRoleBinding granting cluster-admin (K8S-020). Together those two settings give an attacker who lands code in any pod on a poisoned node both an escape to the host filesystem and the API privileges needed to pivot the entire cluster, read every Secret, deploy privileged workloads across all nodes, impersonate any service account.

**References**

- <https://kubernetes.io/docs/concepts/storage/volumes/#hostpath>
- <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- <https://www.cncf.io/blog/2024/04/29/the-dangerous-cluster-admin/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace hostPath volumes with a CSI driver scoped to the specific subtree the workload needs, or use ConfigMap / downwardAPI volumes for non-storage cases. Audit ClusterRoleBindings: cluster-admin should be reserved for a narrow human-operator group with break-glass access, never bound to a ServiceAccount or a broad ``Group``. Even with hostPath in place, removing the cluster-admin grant breaks the API-pivot leg of this chain.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-012: Reusable Workflow Secret Exfiltration { #ac-012 }

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

### AC-013: Caller-Controlled Runner with Token Persistence { #ac-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1133</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow's ``runs-on:`` is computed from an attacker-controllable expression (GHA-036) AND a step in the same workflow writes ``GITHUB_TOKEN`` to persistent storage (GHA-019). The caller (or PR sender) picks which runner the workflow lands on; the workflow then drops its short-lived token onto that runner's filesystem; whoever owns the picked runner harvests the token and acts as the workflow inside the repo.

**References**

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg of the chain. (a) Hard-code ``runs-on:`` or validate the input against an allowlist of known-good labels before the job runs, so the caller can't pick an attacker-controlled runner. (b) Stop writing ``GITHUB_TOKEN`` to disk, use it inline via ``${{ secrets.GITHUB_TOKEN }}`` in the step that needs it. Doing (a) closes the targeting leg; (b) limits blast radius even if (a) is somehow bypassed because the token no longer outlives the step that consumes it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-014: Caller-Controlled Runner with Token Persistence (GitLab) { #ac-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1133</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> exfiltration</span> <span class="pg-tag pg-tag--owasp">gitlab</span>
</div>

A pipeline's ``tags:`` is computed from an attacker-controllable CI variable (GL-032) AND a script line in the same job writes ``CI_JOB_TOKEN`` (or another CI-managed credential) to persistent storage (GL-020). The pipeline trigger picks which tagged runner the job lands on; the job then drops its short-lived token onto that runner's filesystem; whoever owns the picked runner harvests the token and acts as the pipeline against the GitLab API.

**References**

- <https://docs.gitlab.com/ee/ci/runners/configure_runners.html#runner-security>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg of the chain. (a) Hard-code ``tags:`` to a specific runner-tag list, or validate the value against an allowlist in a ``rules:`` guard before the job runs, so the trigger can't pick an attacker-controlled runner. (b) Stop writing ``CI_JOB_TOKEN`` (or other CI-managed credentials) to disk, use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes. Doing (a) closes the targeting leg; (b) limits blast radius even if (a) is somehow bypassed because the token no longer outlives the step that consumes it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-015: Helm chart-supply-chain takeover via legacy + unlocked + plaintext { #ac-015 }

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

Bump every chart to ``apiVersion: v2`` so the in-tree ``Chart.lock`` mechanism is available. Re-run ``helm dependency update`` to populate per-dependency ``sha256:`` digests in the lock and commit it alongside ``Chart.yaml``. Switch each ``dependencies[].repository`` to ``https://``, ``oci://``, or a ``file://`` sibling. Helm 3.8+ pulls OCI-hosted charts over HTTPS by default and is the recommended distribution shape. Removing any *one* of these three legs breaks this chain (the lock catches a swap on the next update; HTTPS catches it before the tarball lands; v2 makes the lock possible in the first place).

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-016: OIDC role drift: ungated GitHub trust meets wildcard AWS authority { #ac-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1556</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">aws</span>
</div>

A GitHub Actions workflow requests an OIDC token without an ``environment:`` gate (GHA-030) AND the AWS IAM role it assumes carries a wildcard ``Action`` (IAM-002). Together, any branch, including a fork PR if the workflow is fork-runnable, can mint a token that maps to a role with broad authority over the account.

**References**

- <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- <https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-and-Access-Management>

<div class="pg-rule__rec" markdown>

**Recommended action**

Close either leg to break the chain. On the GitHub side: require an ``environment:`` key on every job that uses ``id-token: write``, and configure that environment with required reviewers + deployment-branch restrictions. On the AWS side: scope the role's policies to specific actions and resources, replace ``Action: '*'`` with the narrow set the workflow actually needs. Best is both: environment gate + least-privilege role + a ``token.actions.githubusercontent.com:sub`` condition in the role's trust policy that names the specific repo/ref.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-017: Build cache poisoning that lands on a mutable ECR tag { #ac-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1546</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">initial-access -> persistence -> impact</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">aws</span>
</div>

A GitHub Actions workflow's cache key derives from attacker-controllable input (GHA-011) AND the ECR repository it pushes to has mutable image tags (ECR-002). A fork-PR-driven cache poisoning lands compiled artifacts on the cache; the next default-branch build restores them and pushes the resulting image under a tag that consumers pull by name, replacing the previous content for every downstream deployment.

**References**

- <https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/>
- <https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html>
- <https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows>

<div class="pg-rule__rec" markdown>

**Recommended action**

Close either leg to break the chain. On the GitHub side: the cache key must be deterministic from the build's own inputs (lockfile hash, source-tree hash), never from PR-controlled context (``github.head_ref``, ``github.event.*.title``, etc.). On the AWS side: set ``imageTagMutability=IMMUTABLE`` on the ECR repository and reference images by digest in deployment manifests. Best is both: deterministic cache keys + immutable tags + digest-pinned consumers.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-018: Unpinned action lands on deploy job with no environment gate { #ac-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1556</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> impact</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A workflow uses a third-party action pinned by tag rather than commit SHA (GHA-001) AND its deploy job has no ``environment:`` binding (GHA-014). A compromise of the upstream action maintainer's account, or a malicious release re-tagged under the existing version, runs in the deploy job's context without a required-reviewer gate, shipping attacker-controlled code to production on the next workflow trigger.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>
- <https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment>
- <https://www.stepsecurity.io/blog/popular-github-action-tj-actions-changed-files-is-compromised>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every third-party action to a 40-char commit SHA (``actions/checkout@<sha> # v4.1.0``) and put deploy jobs behind a GitHub Environment that requires reviewer approval and restricts deployment branches. Either fix alone breaks the chain, the SHA pin removes the supply-chain leg, the environment gate removes the unattended-deploy leg. Best is both, plus a deployment-branch restriction so only ``main`` / ``release/*`` can reach the gated environment.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-019: Lambda env-secret meets a CI/CD role with PassRole * { #ac-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">credential-access -> privilege-escalation -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">aws</span>
</div>

A Lambda function holds a credential-shaped literal in its env vars (LMB-003) AND a CI/CD service role in the same account grants ``iam:PassRole`` with ``Resource: '*'`` (IAM-004). The first leak gives any read-account principal the credential; the second turns that credential into a role-hop primitive against any IAM role in the account.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-and-Access-Management>
- <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>
- <https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption>

<div class="pg-rule__rec" markdown>

**Recommended action**

Close either leg. On the Lambda side: move every env-var credential into Secrets Manager or SSM SecureString and fetch it at function init; the env vars then carry only the secret's ARN, not the value. On the IAM side: scope ``iam:PassRole`` with ``Resource: <specific-role-ARNs>`` and add an ``iam:PassedToService`` condition. The credential leak is its own compliance failure; the PassRole wildcard is its own; the chain stops being a chain when either is fixed.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-020: Tekton hostPath build workload meets cluster-admin RBAC { #ac-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1611</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="kill-chain phase">initial-access -> privilege-escalation -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">tekton</span> <span class="pg-tag pg-tag--owasp">kubernetes</span>
</div>

A Tekton Task mounts a hostPath volume or shares host namespaces (TKN-004) AND the cluster carries a ClusterRoleBinding granting cluster-admin (K8S-020). Anyone who can land code in a TaskRun has both an escape to the host filesystem and the API privileges needed to pivot the entire cluster, read every Secret, deploy privileged workloads across all nodes, impersonate any service account.

**References**

- <https://tekton.dev/docs/pipelines/tasks/#configuring-volumes>
- <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- <https://tekton.dev/docs/pipelines/auth/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the Task's ``hostPath`` volume with a Workspace (``workspaces`` declaration + per-TaskRun ``persistentVolumeClaim`` / ``emptyDir`` binding). Tekton's native shape for sharing files between steps without exposing the node filesystem. Audit cluster ``ClusterRoleBindings``: cluster-admin should be reserved for a narrow human-operator group with break-glass access, never bound to a ServiceAccount or a broad Group. Even with hostPath in place, removing the cluster-admin grant breaks the API-pivot leg of this chain.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### AC-021: Argo default-SA workflow lands on a default-SA RoleBinding { #ac-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1098.003</span> <span class="pg-tag" title="kill-chain phase">initial-access -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">argo</span> <span class="pg-tag pg-tag--owasp">kubernetes</span>
</div>

An Argo Workflow runs as the namespace default ServiceAccount (ARGO-003) AND a RoleBinding grants permissions to that default SA (K8S-029). Anyone who can submit a Workflow into the namespace runs code under whatever verbs the binding grants, turning ARGO-003 from a hygiene gap into a concrete privilege-escalation primitive.

**References**

- <https://kubernetes.io/docs/concepts/security/rbac-good-practices/#default-service-account>
- <https://argo-workflows.readthedocs.io/en/latest/service-accounts/>
- <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>

<div class="pg-rule__rec" markdown>

**Recommended action**

On the Argo side: set ``spec.serviceAccountName: <workflow-runner>`` on every Workflow / WorkflowTemplate and bind that SA to a least-privilege Role. On the Kubernetes side: never grant verbs to ``default``, every RoleBinding's ``subjects`` should name a workflow-specific SA. The fix on either side breaks the chain. Best is both: explicit per-workflow SAs across every namespace, plus deny rules / OPA policies that block any RoleBinding subject named ``default`` at admission time.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-022: GitLab script injection lands on deploy job with no manual gate { #ac-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1059</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1556</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> impact</span> <span class="pg-tag pg-tag--owasp">gitlab</span>
</div>

A ``.gitlab-ci.yml`` job interpolates an attacker-controlled context field directly into its ``script:`` (GL-002) AND a deploy job in the same file lacks a manual approval / protected ``environment:`` gate (GL-004). A crafted commit title or MR description from any branch the pipeline runs on injects a shell command into the build stage; the deploy stage then ships the resulting artifacts to production unattended.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution>
- <https://docs.gitlab.com/ee/ci/environments/protected_environments.html>
- <https://docs.gitlab.com/ee/ci/yaml/#whenmanual>
- <https://docs.gitlab.com/ee/ci/variables/predefined_variables.html>

<div class="pg-rule__rec" markdown>

**Recommended action**

On the injection side: never interpolate ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` directly into a shell command. Bind the field to a job-scoped ``variables:`` entry and reference the variable inside double quotes (``echo "$TITLE"``), so the shell sees one literal argument rather than interpreted syntax. On the deploy side: gate every job that publishes artifacts, applies infrastructure, or pushes to a registry behind ``when: manual`` plus an ``environment:`` mapped to a *protected* environment in GitLab settings, and use ``rules:``/``only:`` to limit the job to the default branch. Either fix breaks the chain; doing both also closes off the same primitive against future rule additions.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-023: Tekton param injection lands in a privileged or root step { #ac-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1059</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1068</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1611</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">tekton</span>
</div>

A Tekton Task interpolates ``$(params.<name>)`` directly into a step's ``script:`` body without quoting (TKN-003) AND the same step runs ``privileged: true`` / ``runAsUser: 0`` / with node-level ``capabilities.add`` (TKN-002). A crafted PipelineRun param value, supplied via a webhook payload, GitOps merge, or fork-PR-triggered EventListener, injects a shell command that executes inside a kernel-privileged container, the two ingredients for a Kubernetes node escape.

**References**

- <https://tekton.dev/docs/pipelines/tasks/#using-variable-substitution>
- <https://tekton.dev/docs/triggers/eventlisteners/>
- <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution>

<div class="pg-rule__rec" markdown>

**Recommended action**

On the injection side: stop interpolating ``$(params.<name>)`` directly into a step's shell body. Pass the param through ``env:``. Tekton substitutes the param into the env value at run time, and the shell then sees a quoted variable (``"$FOO"``) rather than syntax it can interpret. On the privilege side: drop ``securityContext.privileged: true``, set ``runAsNonRoot: true`` + a non-zero ``runAsUser``, and list only the specific Linux capabilities the step needs (most build tooling needs none). Either fix breaks the chain, a non-privileged container makes the injection a hygiene smell rather than a node-escape primitive, and a quoted param removes the injection regardless of container capabilities. Best is both, plus a Pod Security Admission ``restricted`` label on the namespace to enforce the privilege side at admission time.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-024: OIDC trust drift lands on a mutable ECR tag { #ac-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> impact</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">aws</span>
</div>

A GitHub Actions workflow requests an OIDC token without an environment-protected job (GHA-030) AND an ECR repository has mutable image tags (ECR-002). Any branch or fork PR that triggers the workflow obtains short-lived AWS credentials with no required-reviewer gate; if those credentials reach an ECR push role, the mutable-tag policy lets the workflow overwrite an existing tag (``:latest``, ``:v1.2.3``) and the substituted image propagates to every downstream consumer that pulls by name.

**References**

- <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- <https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html>
- <https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#deployment-protection-rules>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation>

<div class="pg-rule__rec" markdown>

**Recommended action**

Either fix breaks the chain. On the GitHub side: bind any job that requests ``id-token: write`` to a GitHub Environment with required-reviewer protection, and pin the IAM trust policy's ``token.actions.githubusercontent.com:sub`` claim to a specific repo + ref pattern (``repo:owner/repo:ref:refs/heads/main``) so a fork PR can't redeem the role. On the AWS side: set ``imageTagMutability=IMMUTABLE`` on every ECR repository consumed in production, and reference images by digest (``@sha256:...``) in deployment manifests so tag substitution can't propagate even if a push slips through. Best is both: gated OIDC + immutable tags + digest-pinned consumers.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-025: Argo param injection lands in a privileged or root step { #ac-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1059</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1068</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1611</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> privilege-escalation</span> <span class="pg-tag pg-tag--owasp">argo</span>
</div>

An Argo Workflow / WorkflowTemplate interpolates ``{{inputs.parameters.<name>}}`` / ``{{workflow.parameters.<name>}}`` directly into a template's ``script.source`` or container ``command``/``args`` without quoting (ARGO-005) AND the same template runs ``privileged: true`` / ``runAsUser: 0`` / with node-level ``capabilities.add`` (ARGO-002). A crafted param value supplied via an Argo Events Sensor webhook, a CronWorkflow trigger, or a WorkflowEventBinding fork-PR path injects a shell command that executes inside a kernel-privileged container, the two ingredients for a Kubernetes node escape, regardless of what the workflow's ServiceAccount can reach via the API.

**References**

- <https://argo-workflows.readthedocs.io/en/latest/walk-through/parameters/>
- <https://argoproj.github.io/argo-events/sensors/sensor/>
- <https://argo-workflows.readthedocs.io/en/latest/workflow-of-workflows/>
- <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution>

<div class="pg-rule__rec" markdown>

**Recommended action**

On the injection side: stop interpolating ``{{inputs.parameters.<name>}}`` / ``{{workflow.parameters.<name>}}`` directly into a template's shell body. Bind the param to a template ``env:`` entry (``env: [{name: FOO, value: '{{inputs.parameters.foo}}'}]``) and reference the env var inside double quotes (``echo "$FOO"``). Argo substitutes into env values, the shell then sees one literal argument rather than interpreted syntax. On the privilege side: drop ``securityContext.privileged: true``, set ``runAsNonRoot: true`` + a non-zero ``runAsUser``, and list only the specific Linux capabilities the step needs. Either fix breaks the chain, a non-privileged container makes the injection a hygiene smell rather than a node-escape primitive, and a quoted param removes the injection regardless of container capabilities. Best is both, plus a Pod Security Admission ``restricted`` label on the namespace to enforce the privilege side at admission time.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-026: Buildkite injection lands on auto-deploy step with no manual gate { #ac-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1059</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1556</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> impact</span> <span class="pg-tag pg-tag--owasp">buildkite</span>
</div>

A ``pipeline.yml`` interpolates an untrusted Buildkite variable (``$BUILDKITE_MESSAGE``, ``$BUILDKITE_BRANCH``, ``$BUILDKITE_PULL_REQUEST_TITLE``, etc.) into a step's ``command:`` body (BK-003) AND a deploy-named step in the same pipeline runs without a ``manual:`` or ``input:`` gate (BK-007). The combination converts a fork-controllable injection point into an unattended production push, the Buildkite analog of AC-002 / AC-022 on the GitHub and GitLab surfaces.

**References**

- <https://buildkite.com/docs/pipelines/environment-variables>
- <https://buildkite.com/docs/pipelines/block-step>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms>

<div class="pg-rule__rec" markdown>

**Recommended action**

On the injection side: stop interpolating Buildkite metadata variables directly into ``command:`` bodies. Bind the value through ``env:`` instead (``env: { MSG: "$BUILDKITE_MESSAGE" }`` then reference ``"$MSG"`` inside the command) so the shell sees a quoted variable rather than syntax it can interpret. On the gate side: every deploy-named step should carry a ``manual:`` block (or be preceded by a separate ``input:`` step) so a human reviewer acknowledges the deploy. Configure the manual block's ``branches:`` filter and the surrounding step's ``branches:`` filter together so a fork PR build can't trigger production. Either fix breaks the chain; both is best.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-027: Image bakes a credential file AND exposes a remote-access port { #ac-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1190</span> <span class="pg-tag" title="kill-chain phase">credential-access -> initial-access -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">dockerfile</span>
</div>

A ``Dockerfile`` ``COPY`` / ``ADD`` source path names a credential file (``id_rsa``, ``.aws/credentials``, ``.npmrc``, ``.kube/config``, etc.: DF-019) AND the same image ``EXPOSE`` s a sensitive remote-access port (22, 23, 21, 3389, 5900, common database / cache / search ports: DF-013). The image ships a key and a way to reach it from the outside; pulling a public mirror or exfiltrating a single CI build artifact yields both halves of the credential-and-listener pair.

**References**

- <https://docs.docker.com/build/building/best-practices/#exclude-with-dockerignore>
- <https://docs.docker.com/engine/security/>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene>

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential out of the image. Mount it at runtime: a Kubernetes secret (or projected SA token), AWS Secrets Manager / GCP Secret Manager / Vault for cloud creds, or a container-level env var sourced from the orchestrator. The image stops being a leak surface the moment the credential isn't baked in. Drop the ``EXPOSE`` for the remote-access daemon: the container runtime's exec path (``docker exec`` / ``kubectl exec``) covers every legitimate debugging use without opening a port or shipping an extra daemon. Either fix breaks the chain on its own. Add a ``.dockerignore`` rule to keep credential files out of build context as a third layer; the COPY can't bake in what the build never sees.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-028: npm worm propagation primitive co-located { #ac-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1546</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution -> lateral-movement</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">npm</span>
</div>

A repo carries both halves of the Shai-Hulud-class npm worm propagation primitive: a package.json with install-time lifecycle scripts (NPM-004) sits alongside a GitHub Actions workflow that authors sibling workflow files (GHA-048) or pushes to parameterized external repos (GHA-049). The combination is the topology the Shai-Hulud npm worm used to spread, postinstall harvests credentials from every consumer; the workflow leg writes the next stage of the worm into every repo the stolen token can reach.

**References**

- <https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack>
- <https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break either leg: (a) move install-time logic out of ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` into a documented CLI subcommand consumers invoke deliberately, OR (b) remove the workflow's ability to author workflow YAML on the runner and to push to non-allow-listed external repos. With either leg severed the worm has no propagation primitive in this repo. Long-term: rotate every credential the repo's CI can reach if the GHA-048 / GHA-049 finding suggests the workflow has already executed once.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### AC-029: Untrusted trigger reaches a long-lived publish credential { #ac-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1606</span> <span class="pg-tag" title="kill-chain phase">initial-access -> credential-access -> impact</span> <span class="pg-tag pg-tag--owasp">github</span>
</div>

A single workflow file combines an attacker-influenced trigger (GHA-002 / GHA-009 / GHA-013), a long-lived publish or cloud credential (GHA-050 / GHA-005), and an unguarded dependency-install path (GHA-021 / GHA-029). The combination is the Ultralytics / s1ngularity attack lane: an attacker lands code via PR or comment, the same workflow publishes their payload to a public registry under the victim's identity.

**References**

- <https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/>
- <https://nx.dev/blog/s1ngularity-postmortem>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution-PPE>

<div class="pg-rule__rec" markdown>

**Recommended action**

Break the lane at any one leg. Either: (a) re-trigger publish on tag-only / push-to-default-branch (drop ``pull_request_target`` / ``issue_comment`` / ``workflow_run`` from the publish workflow), (b) swap the long-lived token for OIDC Trusted Publishing (PyPI) / a federated identity (AWS) / GitHub's ``id-token: write`` flow, (c) enforce a committed lockfile and registry-integrity verification on the dep install. Doing all three is the long-term posture; doing any one breaks the chain.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-001: Deploy without verifiable provenance (workflow + image) { #xpc-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="kill-chain phase">build -> distribution (no provenance link between them)</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">oci</span>
</div>

The CI workflow doesn't emit SLSA provenance and the image it deploys ships without a build-attestation manifest. The verifier-side contract is broken on both ends, so a downstream consumer pulling the image has no way to prove it came from this workflow's build.

**References**

- <https://slsa.dev/spec/v1.0/levels#build-l2>
- <https://docs.docker.com/build/attestations/slsa-provenance/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Close the verifier loop on both ends. In the workflow, add a provenance-emitting step (``actions/attest-build-provenance`` or the SLSA generic-generator). In the image build, pass ``--attest=type=provenance,mode=max`` to ``docker buildx build`` so the manifest carries a BuildKit attestation manifest. Verify post-deploy with ``cosign verify-attestation`` against the workflow's OIDC identity.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-002: Tag mutability across pipeline + runtime (Dockerfile + K8s) { #xpc-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="kill-chain phase">build -> deploy (tag mutation propagates through both)</span> <span class="pg-tag pg-tag--owasp">dockerfile</span> <span class="pg-tag pg-tag--owasp">kubernetes</span>
</div>

Both the Dockerfile's ``FROM`` line and the Kubernetes workload manifest reference floating image tags. An attacker who pushes a malicious blob under a known tag (stolen registry credentials, compromised upstream CI) affects the build artifact AND the running workload at the same time, with no separate fix-once-and-it's-done place to break the chain.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3>
- <https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin both ends to ``@sha256:<digest>``. In the Dockerfile, rewrite ``FROM python:3.12`` to ``FROM python:3.12@sha256:<digest>``. In the Kubernetes manifest, rewrite ``image: my-org/app:1`` to ``image: my-org/app:1@sha256:<digest>`` (and configure ``imagePullPolicy: IfNotPresent`` so the kubelet doesn't re-resolve on every pod restart). Capture the digest with ``crane digest`` or ``docker buildx imagetools inspect`` and update the digest deliberately in version control when the upstream version moves.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-003: Unverified Helm release flow (chart + image) { #xpc-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="kill-chain phase">package -> distribution -> deploy (no provenance link at any of the three boundaries)</span> <span class="pg-tag pg-tag--owasp">helm</span> <span class="pg-tag pg-tag--owasp">oci</span>
</div>

The Helm chart's ``Chart.lock`` doesn't pin per-dependency digests AND the image the chart deploys lacks a build attestation manifest. Neither the chart contents nor the image bytes are independently verifiable, so a downstream consumer running ``helm install`` has no signed chain of custody between chart authoring and image runtime.

**References**

- <https://helm.sh/docs/topics/chart_repository/#provenance-and-integrity>
- <https://slsa.dev/spec/v1.0/levels#build-l2>

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin both ends of the release flow. In the Helm chart, regenerate ``Chart.lock`` after every dependency update so every entry carries a digest, and gate consumers behind ``helm install --verify`` to enforce the lock at install time. In the image build, pass ``--attest=type=provenance,mode=max`` to ``docker buildx build`` so the manifest carries a BuildKit attestation manifest. Verify post-deploy with ``cosign verify-attestation`` against the workflow's OIDC identity. Both legs together close the producer-to-verifier loop the chart-image pipeline currently has open at every step.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### XPC-004: Token persistence on an unprotected default branch { #xpc-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1552.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="kill-chain phase">credential-access -> persistence (write to default branch -> harvest from artifact)</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">scm</span>
</div>

A workflow persists a CI token or secret into build artifacts (or logs, cache, ``$GITHUB_OUTPUT``) on a repo whose default branch is either unprotected (no protection rule) or allows force-pushes. The combination collapses the attack primitive from 'compromise the build runtime' to 'open a PR that lands a malicious change on main, then fetch the next build's artifacts.' Either leg alone is fixable in isolation; together, the secret is reachable to anyone with write access to the repo.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-6>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes, either alone breaks the chain:
  1. Add a branch protection rule on the default branch with required pull-request reviews and force-push denial (SCM-001 + SCM-007). This forces any change to go through review before it can run with full CI permissions.
  2. Stop persisting tokens to build artifacts (GHA-019). Use OIDC federation with short-lived credentials, mask secret values in logs, and audit any ``::set-output::`` / ``$GITHUB_OUTPUT`` write that includes ``${{ secrets.* }}`` or ``${{ github.token }}``.
Best to fix both — branch protection is the durable control even when a future workflow change reintroduces credential persistence.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-005: End-to-end provenance gap: source unsigned, artifact unsigned { #xpc-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1554</span> <span class="pg-tag" title="kill-chain phase">supply-chain (source tampering -> build tampering, no compensating control at either boundary)</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">scm</span>
</div>

The repo doesn't require signed commits AND the workflow doesn't sign release artifacts. There is no cryptographic chain of custody at either boundary: a tampered commit can land under any contributor's name, and a tampered artifact can ship from any compromised build runtime. Consumers downstream cannot verify what built from what — every release is trust-on-first-use.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-9>
- <https://slsa.dev/spec/v1.0/levels>
- <https://slsa.dev/spec/v1.0/requirements>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes; either alone narrows the chain, both close it:
  1. Enable ``Require signed commits`` on the default branch protection rule (SCM-006). Configure GPG / SSH / S/MIME signing for every contributor so commits land with a verifiable identity.
  2. Add a signing step to the release workflow (GHA-006). ``slsa-framework/slsa-github-generator`` produces a verifiable SLSA L3 provenance attestation; ``sigstore/cosign`` signs the artifact with a keyless Fulcio identity. Publish the signature alongside the artifact and document the verification command in the release notes.
Best to fix both: a signed commit landing in an unsigned release still leaves the build-runtime tampering vector open, and a signed artifact built from unsigned commits still has provenance ambiguity at the source boundary.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

### XPC-006: Unreviewed fork-PR privilege escalation { #xpc-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1199</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.003</span> <span class="pg-tag" title="kill-chain phase">initial-access -> execution (single-identity introduction of the pwn-request primitive; ongoing fork-PR exploitation)</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">scm</span>
</div>

A workflow uses ``pull_request_target`` and checks out the PR head (CRITICAL fork-PR privilege escalation primitive) AND the default branch's protection rule does not require approving reviews. A single insider can introduce or keep the vulnerability alive solo — there is no review gate between a compromised maintainer account and a fork-PR-exploitable workflow on the default branch.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-4>
- <https://securitylab.github.com/research/github-actions-preventing-pwn-requests/>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes; either alone narrows the chain, both close it:
  1. Replace ``pull_request_target`` with ``pull_request`` for any workflow that runs fork-PR code, OR split the workflow so the privileged half (write-scope token, secrets) does NOT check out the PR head and the build half runs in the unprivileged ``pull_request`` context (GHA-002).
  2. Set ``required_approving_review_count >= 1`` in the default branch protection rule so a second identity must acknowledge any change to the workflow file before it merges (SCM-002). Pair with ``require_last_push_approval`` (SCM-014) so a force-push after approval doesn't smuggle the malicious diff back in.
Best to fix both: GHA-002 is the active exploit primitive (every fork PR is a trigger), SCM-002 is the durable control that prevents reintroduction. Without the second, a future commit can reopen the door silently.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-007: Unpinned actions with no automated remediation { #xpc-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.001</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">supply-chain (mutable ingestion -> no automated detection / patch path; manual triage measured in days)</span> <span class="pg-tag pg-tag--owasp">github</span> <span class="pg-tag pg-tag--owasp">scm</span>
</div>

Workflow ``uses:`` references aren't SHA-pinned (so an upstream maintainer compromise propagates to the next workflow run automatically) AND the repo has Dependabot security updates disabled (so the team has no automated alert + PR when the public CVE lands). The exposure window between upstream compromise and remediation is maximized.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3>
- <https://www.cve.org/CVERecord?id=CVE-2025-30066>
- <https://www.cve.org/CVERecord?id=CVE-2025-30154>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes; either alone narrows the chain, both close it:
  1. Pin every ``uses:`` reference to a 40-char commit SHA (GHA-001). The Renovate / Dependabot ``version-update`` config keeps the pins fresh while preserving review of every move. Tag pins (``@v4``, ``@main``) accept silent upstream rewrites; SHA pins do not.
  2. Enable Dependabot security updates on the repo (SCM-005). The bot opens a PR with the minimum-required upgrade against every open advisory on an in-use dependency, so a maintainer is paged within hours of the CVE landing instead of days when someone notices.
Best to fix both: SHA pins remove the *immediate* exposure to upstream tag rewrites; Dependabot remediation closes the *post-disclosure* window during which a CVE is published but no fix is in flight. The tj-actions March 2025 compromise demonstrated both halves of the failure mode in the same incident.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-008: Unreviewed source ships a mutable runtime image { #xpc-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1078.004</span> <span class="pg-tag" title="kill-chain phase">supply-chain (insider source change -> mutable upstream ingestion at build-time)</span> <span class="pg-tag pg-tag--owasp">dockerfile</span> <span class="pg-tag pg-tag--owasp">scm</span>
</div>

The repo's default branch is unprotected (or allows force-pushes) AND the Dockerfile pulls its base image by floating tag rather than digest. An insider can land a tampered ``FROM`` reference change in a single self-merge, AND every subsequent build inherits whatever bytes the upstream registry currently serves under the named tag. Neither the team's review process nor any lockfile has visibility into the runtime image's actual content.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes; either alone narrows the chain, both close it:
  1. Add a branch protection rule on the default branch with required pull-request reviews and force-push denial (SCM-001 / SCM-007). This forces any change to the Dockerfile (and every other source file) to go through review before it can affect the build.
  2. Pin the Dockerfile's ``FROM`` to a digest (``FROM python:3.12@sha256:<hex>``) (DF-001). The build then uses the exact bytes the digest names; an upstream tag rewrite has no effect until a maintainer deliberately updates the digest in the Dockerfile.
Best to fix both: branch protection is the durable control preventing the insider-introduction half, and digest pinning is the durable control preventing the upstream-ingestion half. Either alone leaves the other open.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

### XPC-009: Ingested CVE finding plus mutable runtime image reference { #xpc-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1195.002</span> <span class="pg-tag" title="MITRE ATT&CK technique">MITRE T1525</span> <span class="pg-tag" title="kill-chain phase">supply-chain (current-image vulnerability + unbounded future-image content)</span> <span class="pg-tag pg-tag--owasp">dockerfile</span>
</div>

A SARIF feed (Trivy, Grype, Snyk, etc.) reports at least one CVE against the current image AND the Dockerfile pins its base by floating tag rather than digest. Today's vulnerability set is known; tomorrow's is unbounded. Pinning to a digest keeps the vulnerability snapshot reproducible across builds; updating the digest is then a deliberate, auditable action.

**References**

- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3>
- <https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10>

<div class="pg-rule__rec" markdown>

**Recommended action**

Two fixes; both are needed to close the chain:
  1. Pin the Dockerfile's ``FROM`` to a digest (``FROM python:3.12@sha256:<hex>``) (DF-001). The build then uses the exact bytes the digest names; no upstream tag-rewrite changes the vulnerability set.
  2. Update the digest to a known-clean upstream version the SARIF scanner clears. Capture the digest with ``crane digest`` or ``docker buildx imagetools inspect`` and update the ``FROM`` line in version control. The next build then uses the patched image AND keeps the snapshot consistent across subsequent runs.
Optional but valuable: wire Dependabot or Renovate to auto-PR the digest update when a new clean version publishes (SCM-005 + this chain together close the loop).

</div>

</div>


<!-- chain-catalog:end -->
