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

9 checks · 0 have an autofix patch (``--fix``).

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
