# Dockerfile provider

Parses `Dockerfile` / `Containerfile` documents on disk — text-only
static analysis, no image build, no registry pull, no daemon access.
Multi-stage builds are flattened: rules see the full instruction
stream and decide for themselves whether to scope by stage (e.g.
DF-002 only checks the *final* stage's `USER`).

## Producer workflow

```bash
# --dockerfile-path is auto-detected when Dockerfile/Containerfile
# exists at cwd.
pipeline_check --pipeline dockerfile

# …or pass it explicitly.
pipeline_check --pipeline dockerfile --dockerfile-path docker/api.Dockerfile

# Recursively scan a service directory containing many per-service
# Dockerfiles. The loader matches Dockerfile, Containerfile,
# Dockerfile.<suffix>, and *.Dockerfile by default.
pipeline_check --pipeline dockerfile --dockerfile-path services/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Dockerfile-specific checks

Several checks target Dockerfile concepts that have no direct
analogue in other providers:

- **DF-001** — `FROM` must pin by `@sha256:<digest>`. Reuses the same
  classifier as GL-001 / JF-009 / ADO-009 / CC-003 so the
  floating-tag vocabulary matches across the tool.
- **DF-002** — final stage must run as a non-root `USER`. Multi-stage
  builds: only the runtime image's identity matters, so this rule
  scopes USER tracking to the directives after the *last* `FROM`.
- **DF-003** — `ADD <url>` must carry a BuildKit `--checksum=sha256:`
  flag, otherwise it pulls remote content with no integrity check.
- **DF-006** — `ENV` / `ARG` values are baked into image layers;
  ``docker history`` reads them even after they're overwritten. Any
  literal credential-shaped value (AKIA-prefixed, or a key named
  `*_PASSWORD` / `*_TOKEN` / `*_SECRET` with a non-empty literal) is
  CRITICAL.

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| DF-001 | FROM image not pinned to sha256 digest | HIGH |
| DF-002 | Container runs as root (missing or root USER directive) | HIGH |
| DF-003 | ADD pulls remote URL without integrity verification | HIGH |
| DF-004 | RUN executes a remote script via curl-pipe / wget-pipe | HIGH |
| DF-005 | RUN uses shell-eval (eval / sh -c on a variable / backticks) | HIGH |
| DF-006 | ENV or ARG carries a credential-shaped literal value | CRITICAL |
| DF-007 | No HEALTHCHECK directive declared | LOW |
| DF-008 | RUN invokes docker --privileged or escalates capabilities | HIGH |

---

## DF-001 — FROM image not pinned to sha256 digest
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE, ESF-S-VERIFY-DEPS

Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too — only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommended action**

Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

## DF-002 — Container runs as root (missing or root USER directive)
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Multi-stage builds: only the final stage matters for runtime identity, since intermediate stages don't ship. The check scopes USER to the *last* FROM through end-of-file.

**Recommended action**

Add a ``USER <non-root>`` directive after package install steps (e.g. ``USER 1001`` or ``USER appuser``). Running as root inside a container is not isolation — a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

## DF-003 — ADD pulls remote URL without integrity verification
**Severity:** HIGH · OWASP CICD-SEC-3, CICD-SEC-9 · ESF ESF-S-VERIFY-DEPS, ESF-S-PIN-DEPS

``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommended action**

Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across — that way the verifier runs once at build time, not per-pull.

## DF-004 — RUN executes a remote script via curl-pipe / wget-pipe
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommended action**

Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

## DF-005 — RUN uses shell-eval (eval / sh -c on a variable / backticks)
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

Reuses ``_primitives/shell_eval.scan`` — same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommended action**

Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

## DF-006 — ENV or ARG carries a credential-shaped literal value
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Reuses ``_primitives/secret_shapes`` — flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommended action**

Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history — even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

## DF-007 — No HEALTHCHECK directive declared
**Severity:** LOW

This is a defence-in-depth signal rather than an exploitation indicator — severity is LOW. A missing healthcheck doesn't create a vulnerability on its own, but downstream orchestrators (Kubernetes, ECS, Compose) cannot recover an unhealthy container they cannot detect, and that turns a soft failure (slow leak, deadlock) into a stale-process incident.

**Recommended action**

Declare a ``HEALTHCHECK`` so the orchestrator can detect stuck or zombie containers. Example: ``HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost/healthz || exit 1``. Skip this for builder/multi-stage intermediate images — only the runtime image needs one.

## DF-008 — RUN invokes docker --privileged or escalates capabilities
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can leverage the elevated build.

**Recommended action**

A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out — don't carry the privileged execution into the runtime image.

---

## Adding a new Dockerfile check

1. Create a new module at
   `pipeline_check/core/checks/dockerfile/rules/dfNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/dockerfile/DF-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py dockerfile
   ```
