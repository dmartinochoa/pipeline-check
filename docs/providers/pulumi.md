# Pulumi provider

Static text-only analysis of a Pulumi project on disk. Three
document families are loaded:

* `Pulumi.yaml` — project manifest (`name`, `runtime`, `backend.url`).
* `Pulumi.<stack>.yaml` — per-stack config (`config:`, `secretsprovider`,
  `encryptionsalt`).
* Source files (`__main__.py`, `index.ts`, `main.go`, `Program.cs`, …)
  in the runtime language. Audited via regex-based primitive scans
  (hardcoded credentials, wildcard IAM policies, `StackReference`
  shapes) rather than language-aware AST parsing.

No Pulumi CLI required, no engine execution. Mirrors the Terraform
HCL / CloudFormation / Helm chart-supply-chain providers.

## Producer workflow

```bash
# --pulumi-path auto-detects ./Pulumi.yaml when present.
pipeline_check --pipeline pulumi
pipeline_check --pipeline pulumi --pulumi-path ./Pulumi.yaml
pipeline_check --pipeline pulumi --pulumi-path ./infra/
```

## Supported file families

| File | Parse shape |
|------|-------------|
| `Pulumi.yaml` | Project manifest (`name`, `runtime`, `backend.url`) |
| `Pulumi.<stack>.yaml` | Per-stack config + `secretsprovider` + `encryptionsalt` |
| `*.py` / `*.ts` / `*.js` / `*.go` / `*.cs` | Source-file regex scans |

`node_modules/`, `.venv/`, `venv/`, `.pulumi/`, `bin/`, `obj/`,
`target/`, `dist/`, `build/`, `__pycache__/`, and `.git/` are skipped.

## What it covers

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [PULUMI-001](#pulumi-001) | Pulumi stack uses passphrase-based secret encryption | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-002](#pulumi-002) | Pulumi stack config carries a secret-shaped key in plaintext | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-003](#pulumi-003) | Pulumi source file embeds a hardcoded credential | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-004](#pulumi-004) | Pulumi project uses an insecure state backend | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PULUMI-005](#pulumi-005) | Pulumi source declares an IAM policy with wildcard action + resource | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-006](#pulumi-006) | Pulumi source uses StackReference without project/org guard | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PULUMI-007](#pulumi-007) | Pulumi source declares a publicly accessible cloud resource | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-008](#pulumi-008) | Pulumi source spawns a shell with non-constant input | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-009](#pulumi-009) | Pulumi.yaml runtime does not match any source file | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PULUMI-010](#pulumi-010) | Pulumi stack carries both encryptionsalt and a cloud-KMS provider | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PULUMI-011](#pulumi-011) | Pulumi plugin pulled from a custom download server | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PULUMI-012](#pulumi-012) | Pulumi plugin version unpinned or floating | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PULUMI-013](#pulumi-013) | Pulumi dynamic provider runs arbitrary code at deploy time | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-001: Pulumi stack uses passphrase-based secret encryption { #pulumi-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-321</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``Pulumi.<stack>.yaml`` and fires for any stack where ``secretsprovider`` is missing or set to ``passphrase``. The presence of ``encryptionsalt`` is an additional signal (Pulumi writes the salt only for passphrase-backed stacks). Cloud-KMS providers store an ``encryptedkey`` field instead; either signal is enough to pass the rule.

Skipped when the project has no stack files (no stack yet initialized); the rule has nothing to evaluate in that case. The default Pulumi-service backend (``app.pulumi.com``) is a separate concern, the hosted service stores stack state encrypted at rest in its own envelope but the ``secretsprovider`` field still governs *how* the per-stack secrets are encrypted before upload.

**Known false-positive modes**

- Solo / hobby projects that deliberately use the passphrase posture for portability (no cloud account, no team) trip this rule by design. Suppress per stack with a one-line rationale naming the project's single-author posture. Teams shipping to production should not suppress.

**Seen in the wild**

- Long-running pattern of CI logs / shell histories leaking ``PULUMI_CONFIG_PASSPHRASE`` into team chat, Sentry events, or ticketing systems. The passphrase doubles as the only gate on the stack's secret table; recovery of one leaked value compromises every secret encrypted under it (database URLs, API tokens, OIDC client secrets) indistinguishably from a key-rotation event.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch every stack to a cloud-managed KMS secrets provider. Run ``pulumi stack change-secrets-provider "<url>"`` on each stack with one of:

* ``awskms://<key-id>?region=<region>``
* ``azurekeyvault://<vault-name>.vault.azure.net/<key>/<version>``
* ``gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>``
* ``hashivault://<key-name>``

Each KMS-backed provider keeps the actual encryption key in a managed vault: rotation, per-decrypt audit logs, and IAM-gated access are all properties of the vault, not the Pulumi project. The passphrase posture leaks the entire secret table to anyone who recovers the passphrase, no matter how strong it is. After the switch, ``encryptionsalt`` in ``Pulumi.<stack>.yaml`` is replaced by ``encryptedkey`` (the wrapped KMS-encrypted DEK) and the stack secrets transition into KMS-managed encryption.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-002: Pulumi stack config carries a secret-shaped key in plaintext { #pulumi-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-256</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Walks every ``Pulumi.<stack>.yaml`` ``config:`` block and fires on entries whose key matches a curated secret-shape list (``password`` / ``token`` / ``secret`` / ``apikey`` / ``private_key`` / ``credential`` / ``access_key`` / ``client_secret``) and whose value is not wrapped in ``{secure: ...}``. Wrapped entries (``{"secure": "v1:..."}``) pass — the value is already encrypted with the stack's secretsprovider.

Match is case-insensitive substring on the key (so ``MyApp:DbPassword`` and ``myapp:dbpassword`` both fire). Project-prefixed keys (``my-project:apiToken``) are matched on the full key string, so a value's namespace is included in the surface.

**Known false-positive modes**

- Some non-credential settings happen to contain the word ``key`` (``cache_key_prefix``, ``primary_key``, ``key_name``). The rule's substring matcher will trip on those; suppress per entry with a one-line rationale naming the legitimate identifier-as-key usage. Where possible, rename the config key to avoid the false match.

**Seen in the wild**

- Pattern of plaintext stack-config secrets surfacing in open-source Pulumi project audits: a ``demo`` stack shipped with literal ``dbPassword: changeme123`` was promoted to production by a contributor who didn't realize the ``demo`` value was load-bearing. The passphrase-shaped key escaped review because the value looked obviously fake.

<div class="pg-rule__rec" markdown>

**Recommended action**

Convert every plaintext entry whose key looks like a credential into a Pulumi secret. Run ``pulumi config set --secret <project>:<key> <value>`` on each stack and the CLI re-encrypts the value through the configured secretsprovider (see PULUMI-001) and rewrites the stack file's ``config:`` entry from ``<key>: <plaintext>`` to ``<key>: { secure: <ciphertext> }``. Plaintext entries in the stack file land in git, so anyone with repo read access (or an old clone) can recover the credential indefinitely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-003: Pulumi source file embeds a hardcoded credential { #pulumi-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Scans every source file in the Pulumi project root for high-confidence credential shapes:

* ``AKIA[0-9A-Z]{16}`` / ``ASIA[0-9A-Z]{16}`` — AWS access key prefixes
* ``AIza[0-9A-Za-z_-]{35}`` — Google API keys
* ``ghp_[A-Za-z0-9]{36}`` / ``github_pat_[A-Za-z0-9_]{82}`` — GitHub personal-access tokens
* ``-----BEGIN [A-Z ]*PRIVATE KEY-----`` — PEM-style private key blocks (RSA / EC / OPENSSH / PGP)

Each pattern matches the canonical wire format so the false-positive surface is small. Test / fixture files with deliberate-fake credentials (``AKIAIOSFODNN7EXAMPLE``) are the main exemption class; suppress per file with a one-line rationale.

Skips files outside the Pulumi project root (vendored deps, ``node_modules``, ``.venv``).

**Known false-positive modes**

- Documentation / example files that deliberately include credentials in their canonical-fake form trip the rule by shape (``AKIAIOSFODNN7EXAMPLE`` is intentionally on AWS's docs catalog). Suppress those files explicitly.

**Seen in the wild**

- Long-running pattern in Pulumi repos that begin life as a single-file ``index.ts`` with a quickly-pasted AWS access key for early bootstrapping. The key is then supposed to be replaced before commit; the replacement is forgotten; the repo goes public weeks later, and the key — still active — gets harvested by an opportunistic scanner within hours.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove every hardcoded credential literal and load the value via Pulumi's secret-backed config instead. The two canonical patterns are:

* ``new pulumi.Config().requireSecret("<key>")`` (TypeScript) / ``Config().require_secret("<key>")`` (Python). Reads from the stack's encrypted config table.
* For credentials that already live in a cloud secret manager, read them via the language's native cloud SDK and pass the resulting ``pulumi.Output`` into resource args. Pulumi propagates the secret marker through outputs so downstream stack outputs are also marked encrypted.

After the swap, rotate every credential that ever lived in the source file, even briefly. Anything committed to git stays in clones, backups, and CI caches indefinitely; the rotation is what closes the gap, the code change alone doesn't.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PULUMI-004: Pulumi project uses an insecure state backend { #pulumi-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-922</span>
</div>

Reads ``backend.url`` from every ``Pulumi.yaml`` and fires on:

* ``file://<path>`` — local-disk backend; state lives alongside the working tree, lost on runner teardown, no audit log
* ``http://<host>/...`` — plain HTTP transport; state operations (init, refresh, push) leak full state body + secret payloads to any MITM

Absent ``backend`` field is the Pulumi-service default (safe posture, audited + encrypted) and passes the rule. HTTPS / ``s3://`` / ``gs://`` / ``azblob://`` / ``hashivault://`` URLs also pass.

The rule operates on the manifest text only; it does not verify backend reachability or the configured credentials.

**Known false-positive modes**

- Local-only development sandboxes deliberately use ``file://`` so the engineer can iterate without configuring a backend. The rule still fires; suppress per file with a one-line rationale naming the sandbox policy when the project is genuinely local-only.

**Seen in the wild**

- Pattern of CI runners writing ``file://``-backed Pulumi state to ephemeral disk between deploys: the state is lost on runner teardown, the next ``pulumi up`` rebuilds infrastructure from scratch (deleting and recreating production resources) because Pulumi has no state to reconcile against. The plain-HTTP case is rarer in production but surfaces in self-hosted configurations where an HTTPS reverse proxy was supposed to terminate in front of the backend service.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the state backend off the insecure URL. Three stable options:

* ``app.pulumi.com`` (the default; no ``backend.url`` needed). Audit trail + per-stack ACLs + encrypted-at-rest state.
* ``s3://<bucket>?region=<region>`` with bucket-level default encryption + bucket policy that gates ``GetObject`` to the deploy IAM principal.
* ``azblob://<container>`` or ``gs://<bucket>`` with the equivalent Azure / GCP-side encryption + IAM gates.

Avoid ``file://`` (local disk; no portability, no audit, lost on runner teardown) and plain ``http://`` (in-flight state transit unencrypted; tampering by anyone on the network path). Run ``pulumi login <new-backend>`` and follow the migration prompts; existing state files transfer with secrets preserved.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-005: Pulumi source declares an IAM policy with wildcard action + resource { #pulumi-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-S-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Scans every source file in the Pulumi project root for the IAM policy-document shape that pairs a wildcard ``Action`` with a wildcard ``Resource``:

* ``"Action": "*"`` (or ``"Action": ["*"]``) AND
* ``"Resource": "*"`` (or ``"Resource": ["*"]``) in the same policy statement

Single-wildcard policies (just ``Action: "*"`` or just ``Resource: "*"``) are common in legitimate service-linked roles where the other axis is naturally bounded; the rule only fires when both axes are unbounded.

The pattern is intentionally syntactic: it matches embedded JSON string literals (``policy.JSON.stringify({...})`` / `` policy: pulumi.all([...]).apply(...)``) rather than parsing the source language's AST. This covers the common ``new aws.iam.RolePolicy({policy: JSON.stringify(...)})`` / ``aws.iam.RolePolicy("...", policy=json.dumps(...))`` shapes across TypeScript, Python, Go, and C#.

**Known false-positive modes**

- Sandbox / playground stacks that intentionally use broad policies for short-lived experiments. The rule still fires; suppress per file with a one-line rationale and a TODO to scope the policy before any production usage. Service-linked roles published by AWS that legitimately need wildcards are usually looked up by ARN rather than declared inline, so they don't trip this matcher.

**Seen in the wild**

- Long-running pattern in early-stage Pulumi projects: a single ``allow-everything`` policy attached during the initial bootstrap is never tightened, even after the project ships. Audit reports years later still find the same wildcard role active in production with all consumers depending on its breadth.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the wildcard policy with an explicit action + resource list. AWS' IAM Access Analyzer and Azure's RBAC review feature both surface the minimum rights a workload exercised over the last N days; the tightening pass is mechanical: copy the report's permission set into the policy document and drop the wildcards. Where the policy genuinely needs broad rights (a debugger / break-glass role), gate the policy attachment behind a separate principal that's assumed only via an explicit ``sts:AssumeRole`` (or Azure ``Conditional Access`` equivalent) with MFA and session-recording, rather than handing out the wildcards to every consumer.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PULUMI-006: Pulumi source uses StackReference without project/org guard { #pulumi-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-CHANGE-CONTROL</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Walks every source file for ``new StackReference(<arg>)`` / ``StackReference(<arg>)`` calls and inspects the literal string arg. Fires when the literal lacks two ``/`` separators (the fully-qualified form is ``<org>/<project>/<stack>``).

Pattern variants matched:

* TypeScript / JS: ``new pulumi.StackReference("...")``
* Python: ``pulumi.StackReference("...")``
* Go: ``pulumi.NewStackReference(ctx, "<name>", ...)``
* C#: ``new StackReference("...")``

Variable / interpolated args (``new StackReference(stackName)``) are skipped — the rule can't statically decide their form without language-specific evaluation. Suppress per source file when the indirection is deliberate (e.g. the stack name is itself a config-driven value).

**Known false-positive modes**

- Stack-name indirection via config (``new StackReference(cfg.require("upstream"))``) is invisible to this rule's static scan and won't fire. Conversely, a deliberately-bare reference for a single-org project (common in early-stage repos) trips the rule by shape; suppress per file with a one-line rationale when the org/project pair is fixed and well-known.

**Seen in the wild**

- Pattern of cross-stack data leakage when a Pulumi login context is shared between development and a customer deployment. A bare ``new StackReference("prod")`` in the consumer code resolves against whichever org the current login points at; an engineer who runs the consumer's tests under a customer login binding accidentally reads the customer's prod stack outputs into the development tree. The fully-qualified form would have raised a clear 'no such stack' error and the cross-org access would never have completed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Always pass the fully-qualified ``<org>/<project>/<stack>`` form to ``new StackReference(...)``. The 3-segment form binds the reference to a specific organization and project; a bare stack name (``"prod"``) resolves against whichever org/project the current Pulumi login is pointing at, which can drift between developers and across CI runners. The drift turns into a data-leakage primitive when an attacker who can influence the login binding swaps the referenced stack for one they control. The fully-qualified form also serves as the audit-trail anchor — a reviewer can grep the source for the explicit org/project pair and verify the cross-stack flow.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-007: Pulumi source declares a publicly accessible cloud resource { #pulumi-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-S-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Scans every source file in the Pulumi project root for high-confidence public-access patterns across the three major clouds:

* AWS S3 bucket: ``acl: 'public-read'`` / ``'public-read-write'``, ``aws.s3.BucketAcl.PublicRead``, or a ``BucketPolicy`` granting ``Principal: '*'``.
* Azure Storage container: ``publicAccess: 'Container'`` / ``'Blob'``.
* GCP Storage bucket: ``predefinedAcl: 'publicRead'`` / ``'publicReadWrite'``.

Each pattern matches the canonical wire format so the false-positive surface is small. Patterns operate syntactically — a comment containing the literal ``'public-read'`` won't trip the matcher unless the string also appears in a key-value position.

**Known false-positive modes**

- Public-facing static-content buckets that legitimately need public read access trip this rule by design. Suppress per source file with a one-line rationale naming the bucket's content type and the operator's review of the published data.

**Seen in the wild**

- AWS S3 public-bucket disclosure incidents are a long-running pattern: misconfigured ACLs expose customer data, internal documents, and credential files to anyone with the bucket URL. Cloud providers' own audit reports rank public-bucket misconfigurations among the top sources of disclosure.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the public-access setting from every flagged resource. Three remediation patterns by cloud:

* AWS S3: set ``acl: aws.s3.BucketAcl.Private`` (or drop the ``acl:`` argument entirely; the default is private) and attach a bucket policy that names exactly the principals that need access. For static-content buckets, front the bucket with a CloudFront distribution + OAI rather than enabling public read.
* Azure Blob: set ``publicAccess: 'None'`` on storage containers and grant access via SAS tokens / RBAC scoped to specific principals.
* GCP Storage: drop ``predefinedAcl: 'publicRead'`` / ``'publicReadWrite'`` and use IAM bindings scoped to the principals that need access. Public buckets in GCP also need uniform bucket-level access enabled to prevent ACL-driven escape.

Where the resource genuinely needs public access (public-facing static site, public API), document the intent inline alongside the declaration and confirm the bucket / container content has no sensitive data.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-008: Pulumi source spawns a shell with non-constant input { #pulumi-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Scans every source file for canonical shell-exec primitives that take a single string argument (implying shell interpolation rather than argv array passing):

* Node: ``child_process.exec(...)``, ``child_process.execSync(...)``
* Python: ``os.system(...)``, ``subprocess.run(..., shell=True)``, ``subprocess.Popen(..., shell=True)``
* Go: ``exec.Command("sh", "-c", ...)``
* C#: ``Process.Start("cmd.exe", "/c ...")``

argv-array forms (``child_process.spawn(cmd, [args])``, ``subprocess.run([cmd, *args])``) are skipped — those don't go through a shell and aren't injection primitives in the same way. The rule's focus is on the *shell* path.

**Known false-positive modes**

- Some deploy-time scripts legitimately use shell-exec for portability across CI runners. The right fix is to switch to argv-array forms or a Pulumi-native resource; suppress per file with a one-line rationale when the alternative is impractical.

**Seen in the wild**

- Pattern in Pulumi programs that grew organically out of shell scripts: deployment automation logic that used to be a bash script gets ported to Pulumi by wrapping the original shell-exec calls. The Pulumi program runs with the orchestrator's identity (often broader than the original script's), so the injection-surface inheritance is amplified by the scope expansion.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pulumi programs run at deployment-orchestration time, on a developer's machine or a CI runner with whatever credentials the orchestrator carries. Spawning a shell from inside the Pulumi program — especially with input derived from config, stack outputs, or environment variables — turns the program itself into a command-injection primitive: anyone who can influence the config value (a stack-config push, a promoted stack output, a CI env var) executes arbitrary shell with the orchestrator's identity.

Replace shell-exec primitives with one of:

* A native Pulumi resource (``aws.s3.Bucket``, ``kubernetes.helm.v3.Release``) instead of ``exec("aws s3 mb")`` / ``exec("helm install")``. Pulumi's resource model carries the desired-state + diff semantics that command-line invocation lacks.
* For one-shot deploy-time operations that have no Pulumi resource (running a database migration), use ``pulumi.Command`` (the official command-resource package) with explicit string arrays rather than concatenated shell snippets — the args array bypasses shell-interpolation entirely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PULUMI-009: Pulumi.yaml runtime does not match any source file { #pulumi-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``Pulumi.yaml`` ``runtime:`` and checks whether the project root contains at least one source file matching the runtime's expected extension set. The language-extension map mirrors the recognition logic in the loader (``__main__.py``, ``index.ts``, ``main.go``, ``Program.cs``, ``*.java``).

Projects with multiple language directories under a single Pulumi.yaml (a rare layout) pass when at least one source matches; the rule's intent is to catch the common 'wrong runtime' case, not enforce a single-language project tree.

**Known false-positive modes**

- Multi-language projects where the Pulumi runtime wraps another language (a custom Pulumi component shipped in one language but invoked from another) may legitimately have a runtime declaration that doesn't match the top-level source. Suppress per project with a one-line rationale.

**Seen in the wild**

- Pattern in repositories that migrated from one Pulumi runtime to another (e.g. Python to TypeScript) without updating Pulumi.yaml: ``pulumi up`` either fails confusingly (loader can't find a matching entry-point) or — in the worst case — silently runs against a stale entry-point file the migration left behind.

<div class="pg-rule__rec" markdown>

**Recommended action**

Align ``Pulumi.yaml``'s ``runtime:`` declaration with the language of the source files in the project. The five recognized runtimes:

* ``python`` -> ``__main__.py`` / ``*.py``
* ``nodejs`` -> ``index.ts`` / ``index.js`` / ``*.ts``
* ``go`` -> ``main.go`` / ``*.go``
* ``dotnet`` -> ``Program.cs`` / ``*.cs`` / ``*.fs``
* ``java`` -> ``*.java``

A mismatch — ``runtime: python`` with TypeScript sources, or no source files matching the runtime — means ``pulumi up`` either fails outright or, worse, succeeds against an unintended entry-point file the operator didn't review. Adjusting the runtime declaration to match the actual source language is usually a one-line fix; investigate the underlying cause if the mismatch suggests deeper drift.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PULUMI-010: Pulumi stack carries both encryptionsalt and a cloud-KMS provider { #pulumi-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-323</span>
</div>

Reads ``Pulumi.<stack>.yaml`` and fires when both ``encryptionsalt:`` and ``secretsprovider:`` are set AND the provider URL is a cloud-KMS scheme (``awskms://`` / ``azurekeyvault://`` / ``gcpkms://`` / ``hashivault://``). The shape signals a post-migration stack file where the operator switched to cloud KMS but didn't drop the old passphrase salt.

Distinct from PULUMI-001 (passphrase secretsprovider — active passphrase encryption). This rule catches the cleanup-debt case where KMS is active but evidence of the old passphrase posture lingers.

**Known false-positive modes**

- Operators who deliberately want to maintain the passphrase-recovery option as a safety net trip this rule by design. The right migration discipline is to drop the salt; suppress per file if the operational policy genuinely requires the dual-encryption-recovery fallback.

**Seen in the wild**

- Pattern in Pulumi-using teams that migrate from passphrase to cloud KMS for secrets management: the stack file's ``encryptionsalt`` line is left in place for 'safety' or 'in case we need to roll back', the migration documentation never reaches the cleanup step. The lingering salt becomes the compromise-of-last-resort path if the cloud KMS provider is ever bypassed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the stale ``encryptionsalt`` line from ``Pulumi.<stack>.yaml`` once every secret value has been re-encrypted under the new cloud-KMS provider. The migration sequence is:

1. ``pulumi stack change-secrets-provider "<kms-url>"``. Pulumi rotates every ``secure:`` entry through the new provider and writes the wrapped DEK to ``encryptedkey:``.
2. Manually drop the ``encryptionsalt`` line from the stack file — Pulumi keeps it during the migration as a safety net but doesn't auto-delete.

Without the cleanup, the stack file documents two incompatible encryption posts (passphrase-derived salt + KMS-managed DEK), which:

* Confuses operator audit (which posture is in force?).
* Leaves the salt in git history, which is the only secret-bearing artifact a future attacker would need if the operator ever reverts to the passphrase provider for a single secret.
* Trips static-analysis tools (this one included) that read the salt's presence as evidence of passphrase encryption even when the salt is no longer the active encryption mechanism.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-011: Pulumi plugin pulled from a custom download server { #pulumi-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks the ``plugins:`` block of every ``Pulumi.yaml`` and fires on any entry under ``providers`` / ``analyzers`` / ``languages`` that carries a ``server:`` key. The default (no ``server:``) resolves from the trusted Pulumi registry and passes.

The rule reads the already-parsed ``project.data['plugins']`` structure; it does not fetch the plugin or verify the host's reputation. A ``server:`` pointing at a known-good internal mirror still fires, because the manifest alone can't prove the host is trusted.

**Known false-positive modes**

- A deliberate internal mirror on a host the team controls (``server: https://artifacts.corp.internal/pulumi``) is flagged by shape even though it's a legitimate posture. Suppress per project with a one-line rationale naming the mirror and the checksum-verification step that gates it.

**Seen in the wild**

- Maps to the supply-chain class behind dependency-source substitution attacks: a build pulls native code from an attacker-influenced host and executes it with deploy credentials. Pulumi provider plugins run in-process during ``pulumi up`` with whatever cloud identity the orchestrator holds, so a swapped binary inherits the full deploy blast radius (the same property that made the registry-poisoning and typosquat-source incidents so damaging).

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``server:`` override on the plugin entry and let Pulumi resolve the provider / analyzer binary from the default registry (``get.pulumi.com``). A provider plugin is native code that runs with the orchestrator's cloud credentials during ``pulumi up``, so the download source is part of your trusted compute base.

If a private mirror is genuinely required (air-gapped CI, an internal compliance copy), pin ``server:`` to a host your org controls, serve it over HTTPS, and verify the plugin checksum before it reaches the runner. Treat any change to the ``server:`` value the same as a change to a pinned dependency: reviewed, justified, and logged.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PULUMI-012: Pulumi plugin version unpinned or floating { #pulumi-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks the ``plugins:`` block of every ``Pulumi.yaml`` and fires on any entry under ``providers`` / ``analyzers`` / ``languages`` whose ``version:`` is absent or uses a range / floating spec (a leading ``^`` / ``~`` / ``>`` / ``<`` / ``=`` comparator, a ``*`` or ``x`` wildcard, or the literal ``latest``).

Entries that point at a local build via ``path:`` are skipped: a path plugin carries no registry version to pin, so a missing ``version:`` there is expected. An exact version (``6.18.0``) passes. The rule reads the already-parsed ``project.data['plugins']`` structure and does not contact the registry.

**Known false-positive modes**

- Locally built plugins referenced by ``path:`` are not flagged. A repo that deliberately tracks the latest provider in a sandbox stack trips this rule by shape; suppress per project with a one-line rationale naming the sandbox and the gate that keeps the floating pin out of production.

**Seen in the wild**

- Maps to the unpinned-dependency class: a deploy that resolves a plugin version at run time silently picks up a new (or hijacked) release. The Pulumi engine executes provider plugins in-process with the deploy identity, so a drifted binary runs with full deploy access, the same fresh-carrier-version risk the npm / PyPI cooldown rules address on the registry side.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every plugin entry to an exact version (for example ``version: 6.18.0``). A provider / analyzer plugin is native code the Pulumi engine runs at deploy time; an absent or range-pinned ``version:`` lets that binary change between deploys with no code review and no diff.

Bump the pin through a reviewed commit when you want a new release, so the binary that runs in CI always matches what a human approved. Treat the pin like a lockfile entry, not a hint.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PULUMI-013: Pulumi dynamic provider runs arbitrary code at deploy time { #pulumi-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Scans source files for the dynamic-provider API, scoped to the runtimes where it exists:

* Python: ``pulumi.dynamic.ResourceProvider`` (the base class a dynamic provider subclasses)
* Node / TypeScript: ``pulumi.dynamic`` namespace usage (``pulumi.dynamic.ResourceProvider`` / ``pulumi.dynamic.Resource``)

Go and .NET source files are not scanned because the dynamic-provider API is a Python / Node feature. The rule reads the preserved source text; it does not execute the program.

**Known false-positive modes**

- A dynamic provider with a small, constant, reviewed handler is lower risk than one that reads config or remote input, but it still fires: the engine executes the handler either way and the closure still lands in state. Suppress per file with a one-line rationale when the handler is audited and input-free.

**Seen in the wild**

- Maps to the engine-invoked-code class: deploy-time automation that runs arbitrary handler logic with broad credentials. Because Pulumi serializes the dynamic provider's handler closure into stack state, the rule also covers the state-tampering variant where an attacker who can write the backing state injects code that the next ``pulumi up`` deserializes and runs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Prefer a native Pulumi provider or a reviewed, published component over a dynamic provider. A dynamic provider's ``create`` / ``update`` / ``delete`` handlers are invoked by the Pulumi engine during ``pulumi up``, on the deploy host, with the orchestrator's cloud credentials. The handler closure is also serialized into stack state, so anyone who can edit the handler source (or tamper with the state) gets code execution on the next deploy.

If a dynamic provider is unavoidable, keep the handler code minimal, free of external / config-derived input, and reviewed on every change. Never let a handler shell out or fetch remote code (see PULUMI-008 and PULUMI-007).

</div>

</div>

---

## Adding a new Pulumi check

1. Create a new module at
   `pipeline_check/core/checks/pulumi/rules/pulumiNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(ctx: PulumiContext) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``PulumiContext``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/pulumi/PULUMI-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py pulumi
   ```
