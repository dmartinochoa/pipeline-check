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

20 checks · 7 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [DF-001](#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-002](#df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-003](#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-004](#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-005](#df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-006](#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DF-007](#df-007) | No HEALTHCHECK directive declared | <span class="pg-sev pg-sev--low">LOW</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-008](#df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-009](#df-009) | ADD used where COPY would suffice | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DF-010](#df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DF-011](#df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DF-012](#df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-013](#df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-014](#df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DF-015](#df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DF-016](#df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [DF-017](#df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-018](#df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DF-019](#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [DF-020](#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

---

<div class="pg-rule pg-rule--high" markdown>

## DF-001 — FROM image not pinned to sha256 digest { #df-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too — only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-002 — Container runs as root (missing or root USER directive) { #df-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Multi-stage builds: only the final stage matters for runtime identity, since intermediate stages don't ship. The check scopes USER to the *last* FROM through end-of-file.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``USER <non-root>`` directive after package install steps (e.g. ``USER 1001`` or ``USER appuser``). Running as root inside a container is not isolation — a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-003 — ADD pulls remote URL without integrity verification { #df-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across — that way the verifier runs once at build time, not per-pull.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-004 — RUN executes a remote script via curl-pipe / wget-pipe { #df-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

<div class="pg-rule__rec" markdown>

**Recommended action**

Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-005 — RUN uses shell-eval (eval / sh -c on a variable / backticks) { #df-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Reuses ``_primitives/shell_eval.scan`` — same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-006 — ENV or ARG carries a credential-shaped literal value { #df-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reuses ``_primitives/secret_shapes`` — flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history — even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-007 — No HEALTHCHECK directive declared { #df-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

This is a defense-in-depth signal rather than an exploitation indicator — severity is LOW. A missing healthcheck doesn't create a vulnerability on its own, but downstream orchestrators (Kubernetes, ECS, Compose) cannot recover an unhealthy container they cannot detect, and that turns a soft failure (slow leak, deadlock) into a stale-process incident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare a ``HEALTHCHECK`` so the orchestrator can detect stuck or zombie containers. Example: ``HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost/healthz || exit 1``. Skip this for builder/multi-stage intermediate images — only the runtime image needs one.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-008 — RUN invokes docker --privileged or escalates capabilities { #df-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can leverage the elevated build.

<div class="pg-rule__rec" markdown>

**Recommended action**

A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out — don't carry the privileged execution into the runtime image.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-009 — ADD used where COPY would suffice { #df-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Pure-local ``ADD <path> <dest>`` is functionally identical to ``COPY``, but ships extra-feature surface (URL fetch, tarball auto-extract) that adds nothing and turns a benign-looking filename change into a behavior change. The Docker docs have recommended ``COPY`` for non-URL inputs since 2014.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``ADD ./local`` with ``COPY ./local``. ``ADD`` has two implicit behaviors that make it the wrong default — it fetches HTTP(S) URLs and it auto-extracts ``.tar`` / ``.tar.gz`` archives. Both are easy to invoke accidentally and neither is reproducible. Reserve ``ADD`` for a deliberate URL-pull (covered by DF-003) or an explicit tarball extract.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-010 — apt-get dist-upgrade / upgrade pulls unknown package versions { #df-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution — it can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch — pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-011 — Package manager install without cache cleanup in same layer { #df-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--cwe">CWE-1116</span>
</div>

Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever — final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-012 — RUN invokes sudo { #df-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

``sudo`` inside a Dockerfile is almost always a copy-paste from a host README. Its presence usually means one of three things, all of them wrong: (a) the build is silently running as root and the operator misread it, (b) the image carries an unrestricted ``sudoers`` line that a runtime escape can abuse, or (c) the package install chain depends on TTY-aware ``sudo`` behavior that breaks under non-TTY ``docker build``. None of these cases benefit from keeping the directive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``sudo`` from the ``RUN``. Either the build is already running as root (the default before any ``USER`` directive), in which case ``sudo`` is no-op noise, or the build switched to a non-root ``USER`` and needs root for a specific step — in which case temporarily revert with ``USER root`` for that ``RUN`` and switch back afterward.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-013 — EXPOSE declares sensitive remote-access port { #df-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

``EXPOSE`` is documentation, not a firewall — it doesn't actually open the port. But ``EXPOSE 22`` is a strong signal the image runs sshd, and any remote-access daemon inside the container blows up the threat model: now you have an extra auth surface, an extra service to keep patched, and a way for a compromised app to phone home from the outside. The container runtime / orchestrator's exec path covers every operational use case sshd traditionally served.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``EXPOSE`` line for the remote-access port. If the operator legitimately needs to reach the container, exec into it (``docker exec`` / ``kubectl exec``) — that path uses the orchestrator's auth and audit, doesn't open a network port, and doesn't ship an extra daemon inside the image. Containers should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP alongside the application.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-014 — WORKDIR set to a system / kernel filesystem path { #df-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Subsequent directives in the Dockerfile (``COPY src dest``, ``RUN`` writes, ``ADD …``) resolve relative paths against the active ``WORKDIR``. A ``WORKDIR /sys`` followed by ``COPY conf.txt config.txt`` writes into the kernel's sysfs surface — at best a build-time error, at worst a container-escape primitive that lets a compromised step manipulate cgroups, devices, or kernel config.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move ``WORKDIR`` to a dedicated app directory (``/app``, ``/srv/app``, ``/opt/<service>``). System paths like ``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the ``root`` home are not application directories — pointing the working dir at one means subsequent ``COPY`` / ``RUN`` writes target kernel-exposed namespaces or admin-only configuration.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-015 — RUN grants world-writable permissions (chmod 777 / a+w) { #df-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

World-writable directories under ``/`` are an established container-escape vector: any compromised process running as non-root can drop a payload that root-owned daemons later execute. The rule fires on the literal ``777``, ``a+w``, and ``a+rwx`` modes; the more conservative ``775`` and ``ugo+x`` are not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``chmod 777 <path>`` with the narrowest permissions the workload actually needs. ``chmod 755`` is enough for executables under a read-only root filesystem; ``640`` or ``600`` for files the runtime user reads. ``a+w`` is almost always copy-pasted from a SO answer and almost never the correct fix.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-016 — Image lacks OCI provenance labels { #df-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-017 — ENV PATH prepends a world-writable directory { #df-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-426</span>
</div>

A writable PATH entry that comes before the system bins lets any process inside the container shadow ``ls``, ``ps``, ``apt-get``, ``cat``, etc. by dropping a binary of the same name into the writable dir. On a multi-tenant image — or any image where an exploit can reach the filesystem — this is a free privilege-escalation vector.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other world-writable path in ``PATH`` ahead of the system binary directories. Drop those entries entirely, or place them at the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate binaries always shadow anything dropped into the writable dir at runtime.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-018 — RUN chown rewrites ownership of a system path { #df-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Recognises ``chown`` and ``chgrp`` invocations whose first non-flag path argument resolves under a system directory. The non-recursive case is also flagged because a single ``chown user /etc`` is just as harmful — the recursive flag matters for the size of the blast radius, not for whether it's wrong. Application paths under ``/opt``, ``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't ``chown`` system directories at build time. If the runtime user needs to own a workload-specific subtree, ``COPY --chown=<user>:<group>`` it into the image at the subtree root, or place the workload under a dedicated directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only that path. Granting the runtime user write access to ``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process exploit later steps to stage a binary the system trusts.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-019 — COPY/ADD source path looks like a credential file { #df-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded — the rule reads the literal source token.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-020 — ARG declares a credential-named build argument { #df-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone — ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD`` — even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag — the secret never lands in a layer or in the build history.

</div>

</div>

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
