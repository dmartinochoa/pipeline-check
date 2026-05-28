# Argo CD provider

Parses Argo CD documents from `.yaml` / `.yml` files on disk, text-
only static analysis, no `argocd` binary, no cluster access.
Recognized kinds: `Application`, `ApplicationSet`, `AppProject`
(all under `apiVersion: argoproj.io/v1alpha1`), plus the core `v1
ConfigMap` documents named `argocd-cm` or `argocd-rbac-cm` where
Argo CD's instance-wide config lives. Other documents (including
Argo Workflows CRDs, which belong to the `argo` provider) are
silently skipped.

## Producer workflow

```bash
pipeline_check --pipeline argocd --argocd-path applications/

# A single Application file works too.
pipeline_check --pipeline argocd --argocd-path applications/payments.yaml

# Argo CD + Argo Workflows together; each provider's kind filter
# is disjoint so pointing both at the same dir produces disjoint
# findings, not duplicates.
pipeline_check --pipelines argo,argocd --argo-path ci/ --argocd-path ci/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Argo CD-specific checks

- **ARGOCD-004** walks `data.policy.csv` (and any `data.policy.<role>.csv`)
  on the `argocd-rbac-cm` ConfigMap line by line, ignoring comments
  and explicit denies. The unintuitive bit: `argocd-rbac-cm` is a
  plain `kind: ConfigMap`, not an `argoproj.io` CRD, so this rule
  fires off Kubernetes ConfigMap docs that have to be passed in
  alongside the Application manifests.
- **ARGOCD-007** flags Helm `valueFiles` / `parameters` that
  interpolate generator placeholders (`{{branch}}`, `{{repo}}`)
  without the ApplicationSet setting `spec.goTemplate: true`. Argo
  CD's default fasttemplate substitution is a literal string-splice
  and a generator-controlled value containing YAML structural
  characters lands verbatim in the rendered values.

## What it covers

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ARGOCD-001](#argocd-001) | Argo CD AppProject permits any source repository | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-002](#argocd-002) | Argo CD AppProject permits any destination cluster or namespace | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-003](#argocd-003) | Argo CD Application auto-sync prunes without selfHeal guardrail | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGOCD-004](#argocd-004) | Argo CD RBAC policy grants wildcard authority | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGOCD-005](#argocd-005) | Argo CD repository entry stores plaintext credentials | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGOCD-006](#argocd-006) | Argo CD ApplicationSet PR/SCM generator without project allowlist | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-007](#argocd-007) | Argo CD Helm parameters interpolate generator output without goTemplate | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-008](#argocd-008) | Argo CD Application invokes a config-management plugin | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGOCD-009](#argocd-009) | Argo CD anonymous access enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGOCD-010](#argocd-010) | Argo CD Application targetRevision uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-011](#argocd-011) | Argo CD AppProject cluster-resource whitelist is wide open | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGOCD-012](#argocd-012) | Argo CD AppProject defines no sync windows | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGOCD-013](#argocd-013) | Argo CD Application sets no explicit revisionHistoryLimit | <span class="pg-sev pg-sev--low">LOW</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-001: Argo CD AppProject permits any source repository { #argocd-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Fires when ``spec.sourceRepos`` contains ``"*"`` (case-sensitive). Also fires when the field is missing or empty, matching Argo CD's pre-2.5 default-allow behavior.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``sourceRepos: ['*']`` with the explicit list of Git remotes the project is allowed to deploy from. A wildcard means any user who can create an Application under this project can point it at any repo Argo CD's service account has credentials for, including private internal repos with secrets in their manifests.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-002: Argo CD AppProject permits any destination cluster or namespace { #argocd-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Walks ``spec.destinations[]``. Fires when any entry sets ``server`` or ``name`` to ``"*"`` or sets ``namespace`` to ``"*"``. Both axes evaluated independently; either wildcarded fails the check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``server: '*'`` / ``namespace: '*'`` in ``spec.destinations[]`` with explicit cluster URLs and namespace lists. A wildcard destination lets any Application under the project deploy to kube-system on the management cluster, which converts an Application-create permission into cluster-admin.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGOCD-003: Argo CD Application auto-sync prunes without selfHeal guardrail { #argocd-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-O-DEPLOY-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Walks ``spec.syncPolicy.automated`` on every Application. Fires when ``prune: true`` is set and ``selfHeal`` is either missing or explicitly ``false``. Auto-sync without prune is ignored, the failure mode this rule tracks is the prune-without-detect combination.

<div class="pg-rule__rec" markdown>

**Recommended action**

If you enable ``syncPolicy.automated.prune: true`` (auto-deletes resources that disappear from git), enable ``selfHeal: true`` alongside it so any out-of-band hotfix is detected and reconciled rather than silently kept. The common failure mode is an oncall hand-applies a fix in a fire, then Argo CD prunes it on the next auto-sync because the change isn't in git, recreating the incident.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGOCD-004: Argo CD RBAC policy grants wildcard authority { #argocd-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Parses the ``policy.csv`` (and any ``policy.<role>.csv``) key on ``data:`` in the ``argocd-rbac-cm`` ConfigMap. Fires on lines tokenizing to ``p, <role>, *, *, *, allow``, ``p, <role>, applications, *, */*, allow``, or ``g, <subject>, role:admin``. Comment lines (``#``) and explicit denies (``..., deny``) are ignored.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope each ``p, <role>, <resource>, <action>, <object>, allow`` line in ``argocd-rbac-cm`` ``policy.csv`` to a specific resource / action / object. Replace ``*, *, *, *, allow`` and ``applications, *, */*, allow`` patterns with explicit per-project grants (``applications, get, payments/*, allow``). Restrict ``g, …, role:admin`` bindings to a single named SSO group.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGOCD-005: Argo CD repository entry stores plaintext credentials { #argocd-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Parses ``data.repositories`` (and the legacy ``repository.credentials`` key) on ``argocd-cm`` as YAML. For each entry, fires when a ``password``, ``sshPrivateKey``, ``tlsClientCertKey``, or ``githubAppPrivateKey`` field is a literal non-empty string. Entries using the documented ``passwordSecret`` / ``sshPrivateKeySecret`` indirection pass.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't write ``password`` / ``sshPrivateKey`` / ``tlsClientCertKey`` values directly into the ``repositories`` block of ``argocd-cm``. Move the entry to a separate Kubernetes ``Secret`` carrying the credential (plus the ``argocd.argoproj.io/secret-type: repository`` label) and reference it; or move the whole repo block to a ``Secret`` of type ``repo-creds``. ConfigMap data is world-readable to every namespace member with ``configmaps: get``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-006: Argo CD ApplicationSet PR/SCM generator without project allowlist { #argocd-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Walks ``spec.generators[]``. Fires when a generator entry carries a ``pullRequest`` or ``scmProvider`` key (or a ``git`` generator with ``directories`` / ``files``) AND ``spec.template.spec.project`` is either the literal ``default`` or contains a generator-template placeholder like ``{{repo}}`` / ``{{branch}}`` / ``{{path[0]}}``. Static project + filtered generator passes.

<div class="pg-rule__rec" markdown>

**Recommended action**

When using ``pullRequest`` or ``scmProvider`` generators, pin ``template.spec.project`` to a single static project name (not a generator-interpolated placeholder) and constrain the generator with a ``filters:`` branchMatch / labels block. Otherwise an attacker who opens a PR (or creates a repo in the matched org) materializes a new Argo CD Application under whatever project the placeholder resolves to.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-007: Argo CD Helm parameters interpolate generator output without goTemplate { #argocd-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Walks ``spec.template.spec.source.helm.valueFiles[]`` and ``parameters[].value`` on ApplicationSets, plus the single-Application equivalent. Fires when the value contains a ``{{...}}`` placeholder and the enclosing ApplicationSet doesn't set ``spec.goTemplate: true``. Single-Application Helm sources are checked too: a placeholder there always indicates an upstream ApplicationSet so the same flag must be set.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.goTemplate: true`` on the ApplicationSet (with ``goTemplateOptions: ['missingkey=error']``) so generator placeholders go through Go's template engine, which respects YAML quoting. Without it, Argo CD's default ``fasttemplate`` substitution is a literal string-splice, so a generator-controlled value containing newlines, shell metacharacters, or YAML structural characters lands verbatim in the rendered Helm values.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGOCD-008: Argo CD Application invokes a config-management plugin { #argocd-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Walks ``spec.source.plugin`` on every Application and ApplicationSet template. Fires whenever the field is set with a non-empty ``name``. Helm and Kustomize sources are ignored (they're separately covered by ARGOCD-007 / future Kustomize rules). This is a deliberate noisy-but-correct v1, suppress per-Application once you've reviewed the CMP.

<div class="pg-rule__rec" markdown>

**Recommended action**

CMPs are arbitrary code: Argo CD execs ``generate.command`` inside the repo-server pod at every sync, with whatever manifest content the source repo ships. Audit the CMP's ``discover.find.command`` allowlist, confirm ``generate.command`` doesn't shell out to user-controlled input, and treat each plugin invocation as a build-step review item, not a Kustomize / Helm equivalent.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGOCD-009: Argo CD anonymous access enabled { #argocd-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-306</span>
</div>

Reads ``data.users.anonymous.enabled`` on the ``argocd-cm`` ConfigMap. ConfigMap data values are always stringified by Kubernetes, but the YAML loader can hand us either ``"true"`` or boolean ``true`` depending on how the manifest was written, so both forms fail the check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``users.anonymous.enabled: "true"`` entry from ``argocd-cm`` (or set it to ``"false"``). With anonymous access on, the Argo CD UI / API answers requests carrying no token, and whatever permissions ``role:readonly`` (or the default policy) grants are reachable without authentication.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-010: Argo CD Application targetRevision uses a mutable ref { #argocd-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``spec.source.targetRevision`` (or each entry in ``spec.sources[].targetRevision`` for multi-source apps) and fires when the value matches a mutable-ref shape: ``HEAD``, branch-name literals (``main`` / ``master`` / ``develop`` / ``release-*``), or any non-SHA non-SemVer string. Immutable shapes that pass:

* 40-character hex commit SHA
* SemVer literal (``1.2.3``, ``1.2.3-rc.1``)
* ``v``-prefixed SemVer (``v1.2.3``)

Helm chart sources (``spec.source.chart`` set) follow the same rule: ``targetRevision`` should be a SemVer literal, not a range or branch.

**Known false-positive modes**

- Some staging environments deliberately track ``main`` for fast iteration on dev workloads. The rule still fires; suppress per Application with a one-line rationale naming the environment's intentional drift posture. Production environments should not be suppressed.

**Seen in the wild**

- Long-running pattern of Argo CD deployments tracking ``HEAD`` on the default branch and silently picking up every push to that branch. Force-pushes to the branch (intentional or via maintainer-account compromise) redirect the deploy without any Argo CD-side review; SHA-pinned deployments survive the same incident because the ref content is content-addressed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every Application source to an immutable ref. Three stable shapes:

* ``targetRevision: <40-char-commit-sha>`` for git sources. The SHA binds to specific content; force-push and tag-move can't redirect the deploy.
* ``targetRevision: v1.2.3`` for git sources where signed tags are the org's release convention AND the repo enforces tag-immutability (signed tags + branch protection denying tag-rewrite). Without the protection, treat tags as mutable and pin the SHA instead.
* ``targetRevision: 1.2.3`` for Helm chart references where the chart repo enforces version-immutability (chart museum default, OCI registry default). SemVer pins to a published chart digest.

Branch refs (``main`` / ``master`` / ``HEAD``) follow the branch tip on every reconcile; whoever has push access to the branch controls what Argo CD deploys. This is the GitOps analog of ``GHA-001 actions/checkout@v4`` and carries the same exposure window.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGOCD-011: Argo CD AppProject cluster-resource whitelist is wide open { #argocd-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-862</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Reads ``spec.clusterResourceWhitelist`` from each AppProject and fires when the list contains an entry with ``{group: '*', kind: '*'}`` (the explicit wildcard). The empty-list default passes the rule (it blocks all cluster-scoped writes). Partially-wildcarded entries (``{group: '*', kind: ClusterRole}`` or ``{group: rbac.authorization.k8s.io, kind: '*'}``) also trip the rule because either axis being a wildcard means the other axis can't bound the blast radius.

Pairs with ARGOCD-002 (destinations wildcard, which controls *where* an Application can deploy). This rule controls *what kinds* it can deploy.

**Known false-positive modes**

- Operator-installation projects that legitimately need broad cluster-resource creation rights (the only way to install some operators is via CRD + ClusterRole + ClusterRoleBinding). Suppress per project with a one-line rationale naming the operator and the install procedure that requires the broad rights.

**Seen in the wild**

- Common over-provisioning pattern: a contributor adds ``clusterResourceWhitelist: [{group: '*', kind: '*'}]`` to an AppProject during an operator install, never tightens it back. Months later, an Application under that project is deployed with a malicious ClusterRoleBinding (via a compromised git commit or a typo in a values file); the binding lands without any AppProject-side gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict ``spec.clusterResourceWhitelist`` to the exact (group, kind) tuples the project's Applications need. The default (an empty list) blocks all cluster-scoped writes, which is the safest posture for namespace-scoped workloads. A wildcard (``{group: '*', kind: '*'}``) allows the project to install ClusterRoleBindings, CustomResourceDefinitions, ValidatingAdmissionWebhooks, and PodSecurityPolicies — every category capable of cluster takeover.

Typical narrow allowlist for a workload project:

    spec:
      clusterResourceWhitelist: []
      namespaceResourceWhitelist:
        - { group: '', kind: ConfigMap }
        - { group: '', kind: Service }
        - { group: apps, kind: Deployment }

Projects that legitimately install cluster-scoped resources (an operator project, a CRD-management project) should enumerate the specific kinds, never wildcards.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGOCD-012: Argo CD AppProject defines no sync windows { #argocd-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-DEPLOY-MON</span> <span class="pg-tag pg-tag--cwe">CWE-285</span>
</div>

Reads ``spec.syncWindows`` from each AppProject and fires when the field is missing or empty AND the project's ``destinations`` include a production-shaped namespace (literal ``prod``, ``production``, or any namespace name containing ``prod``). The production-shape heuristic keeps the rule from firing on dev / staging projects where instant reconciliation is the deliberate posture.

Sync windows complement ARGOCD-003 (automated sync without selfHeal) at the schedule layer: ARGOCD-003 catches the drift-revert hazard, this catches the change-freeze hazard.

**Known false-positive modes**

- Hosting / SaaS environments that intentionally deploy continuously across all hours (24/7 always-on update cadence) trip this rule. Suppress per project with a one-line rationale naming the continuous-deploy policy. Most production environments benefit from at least a weekend / overnight freeze.

**Seen in the wild**

- Common change-control gap: a Friday-evening force-push to the manifests repo lands in production within minutes via Argo CD's automated sync. The on-call team is paged for the resulting outage hours later, by which point the responsible contributor is offline. Sync windows would have blocked the deploy until Monday's business hours, buying time for a manual review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Define explicit ``spec.syncWindows`` entries on every AppProject that gates production deploys. A sync window is a calendar-style rule that allows or denies automated / manual sync during specific schedules. Without windows, every git commit can be reconciled to production instantly — fine for staging, dangerous for prod where off-hours change-freezes (weekend / on-call rotations / active-incident windows) are normal posture.

Example: deny automated sync outside business hours but still allow manual sync (for break-glass deploys):

    spec:
      syncWindows:
        - kind: deny
          schedule: "0 18 * * *"
          duration: 14h
          applications: ['*']
          manualSync: true   # operators can still sync manually

Pair with ``manualSync: false`` on incident-window blackouts to fully freeze, and with a separate ``kind: allow`` window for the release-rehearsal cadence.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ARGOCD-013: Argo CD Application sets no explicit revisionHistoryLimit { #argocd-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-C-AUDIT</span> <span class="pg-tag pg-tag--cwe">CWE-770</span>
</div>

Reads ``spec.revisionHistoryLimit`` and fires when the field is missing or set to ``null``. Explicit 0 also fires (history disabled entirely is rarely the intended posture — operators usually want at least a 1-2 entry rollback window). The rule is informational-leaning LOW: storage bloat and prolonged-secret-exposure are real but slow-moving risks, not exploitable surfaces an attacker can compromise in isolation.

**Known false-positive modes**

- Sandbox / experimental Applications where rollback is irrelevant trip this rule by design. Suppress per Application with a one-line rationale.

**Seen in the wild**

- Stale-secret pattern in older Argo CD versions: an Application that referenced a secret directly in a manifest (later moved to a sealed-secret / external secret reference) retains the original plaintext manifest in revision history. ``argocd app history`` and the controller API surface the old manifest verbatim, including the plaintext value, until the revision history limit is reached.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.revisionHistoryLimit`` to an explicit small integer (5-20 is the typical range) on every Application. The field caps how many prior synced revisions Argo CD retains for rollback. Unbounded retention keeps stale manifests (and any secrets they referenced) accessible via the Argo CD API indefinitely and grows the controller's storage footprint without bound.

Example:

    spec:
      revisionHistoryLimit: 10  # keep last 10 syncs for rollback

Pick the cap based on the application's rollback need: a stateless web service rarely benefits from more than 5 history entries; an infrastructure controller managing external state may want 20 for forensic comparison across longer windows.

</div>

</div>

---

## Adding a new Argo CD check

1. Create a new module at
   `pipeline_check/core/checks/argocd/rules/argocdNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(ctx: ArgoCDContext) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``ArgoCDContext``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/argocd/ARGOCD-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py argocd
   ```
