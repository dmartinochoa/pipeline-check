# Modelfile provider

Parses Ollama `Modelfile` declarations on disk, text-only static
analysis, no model pull, no Ollama daemon. A Modelfile is the
declarative recipe that pins a model into the local registry, so this
provider is the "Dockerfile of models": the MODEL-* rules reason over
the `FROM` base model and `ADAPTER` LoRA references a Modelfile
declares. It is the static, declaration-side complement to the
CI-script AI rules (GHA-120/121/122, GL-045..049) that catch model
pulls in build scripts.

## Producer workflow

```bash
# Defaults to scanning the working tree for a Modelfile.
pipeline_check --pipeline modelfile

# …or pass it explicitly.
pipeline_check --pipeline modelfile --modelfile-path models/chat.Modelfile

# Recursively scan a directory. The loader matches Modelfile,
# *.Modelfile, and Modelfile.<suffix> by default.
pipeline_check --pipeline modelfile --modelfile-path models/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Modelfile-specific checks

The MODEL-* pack covers the model supply chain a Modelfile declares:

- **MODEL-001**, the `FROM` base model must pin an immutable tag or
  `@sha256:` digest rather than a bare name or `:latest`. The
  model-registry analogue of GHA-001 / DF-001.
- **MODEL-002**, a `FROM hf.co/...` / `huggingface.co/...` base model
  is pulled straight from a third-party hub, bypassing the curated
  Ollama library (the source-trust axis).
- **MODEL-003**, a `FROM ./model.gguf` local weights blob has no
  registry provenance, and a `.bin` / `.pt` import is pickle-backed.
- **MODEL-004**, an `ADAPTER` LoRA pulled from a remote source can
  re-steer the model's behavior and deserves the same pin-and-verify
  treatment as the base model.

## What it covers

4 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [MODEL-001](#model-001) | Base model pulled without a pinned reference | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MODEL-002](#model-002) | Base model pulled from a third-party hub | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [MODEL-003](#model-003) | Base model loaded from a local unverified weights blob | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [MODEL-004](#model-004) | LoRA adapter applied from a remote source | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## MODEL-001: Base model pulled without a pinned reference { #model-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a ``FROM`` whose reference is a registry / hub model (``llama3``, ``library/llama3``, ``hf.co/org/model``) carrying no tag or an explicit ``:latest``. Does NOT fire on a specific tag, an ``@sha256:`` digest, or a local weights file (covered by MODEL-003). Pulling a third-party hub model is sharpened separately by MODEL-002.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the base model to an immutable reference. Prefer an ``@sha256:`` digest (``FROM library/llama3@sha256:...``); failing that, pin a specific, stable tag (``FROM llama3:8b-instruct-q4_0``) rather than a bare name or ``:latest``, both of which the publisher can move. A pinned reference is what makes a swapped-weights or swapped-template attack show up as a diff in your Modelfile instead of landing silently on the next pull.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MODEL-002: Base model pulled from a third-party hub { #model-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a ``FROM`` whose reference begins with ``hf.co/`` or ``huggingface.co/``. This is the source-trust axis; whether that same reference is also unpinned is reported separately by MODEL-001.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat a ``hf.co`` / ``huggingface.co`` base model as an untrusted dependency: vet the uploader, prefer a first-party or curated Ollama-library model, and if the hub model is required pin it to an ``@sha256:`` digest (MODEL-001), prefer GGUF / safetensors over pickle-backed formats, and review the baked-in ``TEMPLATE`` / ``SYSTEM`` the import carries.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## MODEL-003: Base model loaded from a local unverified weights blob { #model-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a ``FROM`` whose reference is a local path (``./``, ``/``, ``~/``, ``../``) or a bare weights filename (``.gguf`` / ``.safetensors`` / ``.bin`` / ``.pt`` / ``.pth``). Pickle-backed extensions are called out in the finding because they deserialize arbitrary code at load.

<div class="pg-rule__rec" markdown>

**Recommended action**

Source the base model from a pinned registry / hub reference (MODEL-001) with a recorded digest rather than a loose local weights file, or, if a local file is required, record and verify its checksum out of band and prefer GGUF / safetensors over pickle-backed ``.bin`` / ``.pt`` formats. A committed binary blob has no provenance a reviewer can check.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## MODEL-004: LoRA adapter applied from a remote source { #model-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on an ``ADAPTER`` whose reference is not a local file (a ``hf.co`` / ``huggingface.co`` pull or a bare registry-style name). A local adapter file does not fire; pin / verify it out of band.

<div class="pg-rule__rec" markdown>

**Recommended action**

Vet and pin the adapter the same way as the base model: prefer a local, checksum-verified adapter file, or pin a remote one to an ``@sha256:`` digest and review who controls it. An adapter re-steers the model's behavior, so an untrusted or mutable one is a behavior-injection vector.

</div>

</div>

---

## Adding a new Modelfile check

1. Create a new module at
   `pipeline_check/core/checks/modelfile/rules/modelNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(ctx: ModelfileContext) -> list[Finding]`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``ModelfileContext``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/modelfile/MODEL-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py modelfile
   ```
