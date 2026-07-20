# Dockerfile provider

Parses `Dockerfile` / `Containerfile` documents on disk, text-only
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

- **DF-001**, `FROM` must pin by `@sha256:<digest>`. Reuses the same
  classifier as GL-001 / JF-009 / ADO-009 / CC-003 so the
  floating-tag vocabulary matches across the tool.
- **DF-002**, final stage must run as a non-root `USER`. Multi-stage
  builds: only the runtime image's identity matters, so this rule
  scopes USER tracking to the directives after the *last* `FROM`.
- **DF-003**, `ADD <url>` must carry a BuildKit `--checksum=sha256:`
  flag, otherwise it pulls remote content with no integrity check.
- **DF-006**, `ENV` / `ARG` values are baked into image layers;
  ``docker history`` reads them even after they're overwritten. Any
  literal credential-shaped value (AKIA-prefixed, or a key named
  `*_PASSWORD` / `*_TOKEN` / `*_SECRET` with a non-empty literal) is
  CRITICAL.

## What it covers

31 checks · 7 have an autofix patch (``--fix``).

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
| [DF-021](#df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-022](#df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DF-023](#df-023) | ENV sets a dynamic-loader hijack variable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-024](#df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-025](#df-025) | RUN writes a registry auth token into a Docker layer | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DF-026](#df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-027](#df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-028](#df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-029](#df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DF-030](#df-030) | ENV NODE_OPTIONS preloads code or opens an inspector | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DF-031](#df-031) | COPY --from external image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## DF-001: FROM image not pinned to sha256 digest { #df-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Seen in the wild**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-002: Container runs as root (missing or root USER directive) { #df-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Multi-stage builds: only the final stage matters for runtime identity, since intermediate stages don't ship. The check scopes USER to the *last* FROM through end-of-file.

**Seen in the wild**

- [CVE-2019-5736](https://www.cve.org/CVERecord?id=CVE-2019-5736) (runC host breakout): a malicious container running as root could overwrite the host's runC binary and compromise every other container on the node. Non-root containers were not exploitable.
- [CVE-2022-0492](https://www.cve.org/CVERecord?id=CVE-2022-0492) (cgroups v1 escape via release_agent): root inside a container with CAP_SYS_ADMIN could write to the host's release_agent file and execute arbitrary host code. Containers running as a non-root UID side-stepped the exploit class entirely.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``USER <non-root>`` directive after package install steps (e.g. ``USER 1001`` or ``USER appuser``). Running as root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-003: ADD pulls remote URL without integrity verification { #df-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Known false-positive modes**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-004: RUN executes a remote script via curl-pipe / wget-pipe { #df-004 }

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

## DF-005: RUN uses shell-eval (eval / sh -c on a variable / backticks) { #df-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-006: ENV or ARG carries a credential-shaped literal value { #df-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-007: No HEALTHCHECK directive declared { #df-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

This is a defense-in-depth signal rather than an exploitation indicator, severity is LOW. A missing healthcheck doesn't create a vulnerability on its own, but downstream orchestrators (Kubernetes, ECS, Compose) cannot recover an unhealthy container they cannot detect, and that turns a soft failure (slow leak, deadlock) into a stale-process incident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare a ``HEALTHCHECK`` so the orchestrator can detect stuck or zombie containers. Example: ``HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost/healthz || exit 1``. Skip this for builder/multi-stage intermediate images, only the runtime image needs one.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-008: RUN invokes docker --privileged or escalates capabilities { #df-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can exploit the elevated build.

<div class="pg-rule__rec" markdown>

**Recommended action**

A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out, don't carry the privileged execution into the runtime image.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-009: ADD used where COPY would suffice { #df-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Pure-local ``ADD <path> <dest>`` is functionally identical to ``COPY``, but ships extra-feature surface (URL fetch, tarball auto-extract) that adds nothing and turns a benign-looking filename change into a behavior change. The Docker docs have recommended ``COPY`` for non-URL inputs since 2014.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``ADD ./local`` with ``COPY ./local``. ``ADD`` has two implicit behaviors that make it the wrong default. It fetches HTTP(S) URLs and it auto-extracts ``.tar`` / ``.tar.gz`` archives. Both are easy to invoke accidentally and neither is reproducible. Reserve ``ADD`` for a deliberate URL-pull (covered by DF-003) or an explicit tarball extract.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-010: apt-get dist-upgrade / upgrade pulls unknown package versions { #df-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-011: Package manager install without cache cleanup in same layer { #df-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--cwe">CWE-1116</span>
</div>

Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever, final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-012: RUN invokes sudo { #df-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

``sudo`` inside a Dockerfile is almost always a copy-paste from a host README. Its presence usually means one of three things, all of them wrong: (a) the build is silently running as root and the operator misread it, (b) the image carries an unrestricted ``sudoers`` line that a runtime escape can abuse, or (c) the package install chain depends on TTY-aware ``sudo`` behavior that breaks under non-TTY ``docker build``. None of these cases benefit from keeping the directive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``sudo`` from the ``RUN``. Either the build is already running as root (the default before any ``USER`` directive), in which case ``sudo`` is no-op noise, or the build switched to a non-root ``USER`` and needs root for a specific step, in which case temporarily revert with ``USER root`` for that ``RUN`` and switch back afterward.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-013: EXPOSE declares sensitive remote-access port { #df-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

``EXPOSE`` is documentation, not a firewall. It doesn't actually open the port. But ``EXPOSE 22`` is a strong signal the image runs sshd, and any remote-access daemon inside the container blows up the threat model: now you have an extra auth surface, an extra service to keep patched, and a way for a compromised app to phone home from the outside. The container runtime / orchestrator's exec path covers every operational use case sshd traditionally served.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``EXPOSE`` line for the remote-access port. If the operator legitimately needs to reach the container, exec into it (``docker exec`` / ``kubectl exec``). That path uses the orchestrator's auth and audit, doesn't open a network port, and doesn't ship an extra daemon inside the image. Containers should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP alongside the application.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-014: WORKDIR set to a system / kernel filesystem path { #df-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Subsequent directives in the Dockerfile (``COPY src dest``, ``RUN`` writes, ``ADD …``) resolve relative paths against the active ``WORKDIR``. A ``WORKDIR /sys`` followed by ``COPY conf.txt config.txt`` writes into the kernel's sysfs surface, at best a build-time error, at worst a container-escape primitive that lets a compromised step manipulate cgroups, devices, or kernel config.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move ``WORKDIR`` to a dedicated app directory (``/app``, ``/srv/app``, ``/opt/<service>``). System paths like ``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the ``root`` home are not application directories, pointing the working dir at one means subsequent ``COPY`` / ``RUN`` writes target kernel-exposed namespaces or admin-only configuration.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-015: RUN grants world-writable permissions (chmod 777 / a+w) { #df-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

World-writable directories under ``/`` are an established container-escape vector: any compromised process running as non-root can drop a payload that root-owned daemons later execute. The rule fires on octal ``777`` / ``0777`` and on any ``chmod`` ``+`` operator whose who-set is empty or contains ``a`` / ``o`` and whose mode flags include ``w`` (so ``a+w``, ``a+wx``, ``a+rwx``, ``o+w``, ``ugo+w``, ``go+rw``, ``+w``, ``+rwx`` all flag). ``u+w`` and ``g+w`` are not flagged, neither grants the world-writable bit.

**Known false-positive modes**

- Test fixtures or scratch builds that intentionally share a directory across multiple non-root users may legitimately use ``777``. Suppress with an ignore-file entry rather than weakening the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``chmod 777 <path>`` with the narrowest permissions the workload actually needs. ``chmod 755`` is enough for executables under a read-only root filesystem; ``640`` or ``600`` for files the runtime user reads. ``a+w`` is almost always copy-pasted from a SO answer and almost never the correct fix.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## DF-016: Image lacks OCI provenance labels { #df-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Known false-positive modes**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-017: ENV PATH prepends a world-writable directory { #df-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-426</span>
</div>

A writable PATH entry that comes before the system bins lets any process inside the container shadow ``ls``, ``ps``, ``apt-get``, ``cat``, etc. by dropping a binary of the same name into the writable dir. On a multi-tenant image, or any image where an exploit can reach the filesystem, this is a free privilege-escalation vector.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other world-writable path in ``PATH`` ahead of the system binary directories. Drop those entries entirely, or place them at the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate binaries always shadow anything dropped into the writable dir at runtime.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-018: RUN chown rewrites ownership of a system path { #df-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Recognizes ``chown`` and ``chgrp`` invocations whose first non-flag path argument resolves under a system directory. The non-recursive case is also flagged because a single ``chown user /etc`` is just as harmful, the recursive flag matters for the size of the blast radius, not for whether it's wrong. Application paths under ``/opt``, ``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged, nor are the application source/data subtrees ``/usr/src`` (the ``node`` image's ``/usr/src/app`` WORKDIR) and ``/usr/share`` (web/data roots); those hold no trusted binaries on ``PATH``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't ``chown`` system directories at build time. If the runtime user needs to own a workload-specific subtree, ``COPY --chown=<user>:<group>`` it into the image at the subtree root, or place the workload under a dedicated directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only that path. Granting the runtime user write access to ``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process exploit later steps to stage a binary the system trusts.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-019: COPY/ADD source path looks like a credential file { #df-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Known false-positive modes**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-020: ARG declares a credential-named build argument { #df-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Known false-positive modes**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-021: RUN pip install bypasses TLS or uses an HTTP index { #df-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Three shapes are detected: ``pip install --trusted-host <host>``, ``pip install -i http://...`` (or ``--index-url http://...``), and ``pip install --extra-index-url http://...``. All three tell pip to accept whatever the upstream returns without certificate verification. The result is a build-time supply-chain MITM surface: anyone able to inject responses on the network path between the build host and the index can ship arbitrary wheels into the image. Complements the generic TLS-bypass primitive (which catches ``pip config set global.trusted-host``) by covering the per-invocation flag form most teams actually reach for.

**Known false-positive modes**

- An internal index served over plain HTTP on a private network (no internet path) is the typical justification for the flag. Fix the index (terminate TLS at a reverse proxy, or install the internal CA into the image) rather than leaving the bypass in the Dockerfile.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``--trusted-host`` and switch any ``-i`` / ``--index-url`` / ``--extra-index-url`` to ``https://``. If the internal index has a self-signed certificate, install the CA into the image's truststore (``ca-certificates`` + ``update-ca-certificates``) instead of telling pip to skip verification. ``--trusted-host`` whitelists the host across the entire pip invocation, so a single ``RUN`` line ends up fetching every dependency over an unverified connection.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-022: RUN uses npm install instead of npm ci { #df-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Mirrors GHA-022 / GL-022 / JF-021 (CI-side lockfile integrity) at the image-build layer. The build-time consequence is the same shape: dependency resolution happens against the live registry rather than against the committed lockfile, so the image ends up carrying whatever the registry served at build time rather than the set the team audited. The rule fires on bare ``npm install`` / ``npm i`` as well as on flagged variants (``--no-package-lock``, ``--force``, ``--legacy-peer-deps``) which all defeat the lockfile contract one way or another.

**Known false-positive modes**

- Multi-stage build whose runtime image copies in a pre-computed ``node_modules`` and never installs at build time is unaffected, the rule only fires on directives that actually invoke ``npm install``.
- ``npm install --production`` is still flagged: it ignores ``devDependencies`` but still re-resolves and mutates the lockfile. Use ``npm ci --omit=dev`` instead.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch to ``npm ci`` (or ``yarn install --frozen-lockfile`` / ``pnpm install --frozen-lockfile`` for those toolchains). ``npm ci`` requires a ``package-lock.json`` and fails the build if it disagrees with ``package.json``; it never rewrites the lockfile and never installs packages outside the locked set. ``npm install`` does the opposite: it resolves ranges in ``package.json`` at build time and happily mutates the lockfile to fit the resolution, so a transient dependency the team never reviewed can land in the image.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-023: ENV sets a dynamic-loader hijack variable { #df-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-426</span>
</div>

``LD_PRELOAD``, ``LD_LIBRARY_PATH``, and ``LD_AUDIT`` are consulted by ``ld-linux`` for every dynamically-linked binary the image runs. A baked-in value gives an attacker who can drop a file inside the container (via a writable mount, a vulnerable upload handler, a build-stage hold-over) the ability to hook ``libc`` calls in privileged processes, intercept TLS, or shim ``execve`` to reroute commands. ``LD_LIBRARY_PATH`` pointing at a writable directory is the milder shape of the same risk: a planted ``libc.so.6`` shadows the system lib for every later binary.

**Known false-positive modes**

- Sanitizer-instrumented images (``LD_PRELOAD=libasan.so``) and APM agent hooks (``LD_PRELOAD=/opt/dynatrace/...``) are legitimate. Suppress the finding for the specific Dockerfile with a one-line rationale; the rule deliberately catches the pattern because the same shape is the standard loader-hijack escalation primitive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't bake ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` / ``LD_AUDIT`` into the image. If a specific binary needs a non-standard library lookup, set the env var in the binary's own ``ENTRYPOINT`` wrapper so the override is scoped to that process, or, better, configure ``/etc/ld.so.conf.d/`` and rerun ``ldconfig`` at build time. A baked-in ``LD_*`` value applies to every process the image launches, including any shell an attacker reaches after an exploit.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-024: RUN npm/yarn/pnpm install runs lifecycle scripts { #df-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``npm install`` / ``npm ci`` / ``npm i`` (non-global), ``pnpm install`` / ``pnpm i``, and ``yarn install`` / bare ``yarn`` in a ``RUN`` body when ``--ignore-scripts`` is absent from the same line. Detection short-circuits when the same Dockerfile sets ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` (``npm``), ``ENV YARN_ENABLE_SCRIPTS=false`` (yarn berry), or ``ENV CI=true`` is paired with an ``.npmrc`` configured to disable scripts (the env-level kill-switch is detected; the rule trusts ``.npmrc`` only when it's also written by the Dockerfile via ``echo ignore-scripts=true >> .npmrc``). Complements DF-022 (``npm ci`` vs ``npm install``), which guards lockfile integrity; DF-024 guards lifecycle-script execution. A pinned lockfile does not help when the pinned version is the malicious one, only ``--ignore-scripts`` does.

**Known false-positive modes**

- Images that build native modules via ``node-gyp`` need the lifecycle scripts to compile bindings (``better-sqlite3``, ``sharp``, ``canvas``, ...). The fix is per-package: keep the top-level install on ``--ignore-scripts``, then ``RUN npm rebuild better-sqlite3`` afterward, scoped to the audited package. Suppress with a one-line rationale only when an engineer has confirmed every script-running dep is first-party or pinned to a hash.

**Seen in the wild**

- Shai-Hulud npm worm (2026): postinstall scripts in compromised packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, used the stolen tokens to publish more compromised packages and push malicious workflow files into victim repos. ``--ignore-scripts`` neutralizes the postinstall primitive at install time.
- TanStack / Mistral npm compromise (May 2026): 84 versions across 42 packages published in minutes, each carrying a credential-stealing ``postinstall``. Lockfile pinning did not help (the pinned tag itself was poisoned); ``--ignore-scripts`` would have stopped execution.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass ``--ignore-scripts`` to every ``npm`` / ``npm ci`` / ``pnpm install`` / ``yarn install`` invocation in the Dockerfile, or set ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` / ``ENV YARN_ENABLE_SCRIPTS=false`` before the install line. Lifecycle scripts (``preinstall``, ``install``, ``postinstall``, ``prepare``) are the blast radius of the Shai-Hulud / TanStack / axios incidents, a single compromised dependency in the transitive tree runs arbitrary code with the build container's credentials. ``--ignore-scripts`` removes that primitive without affecting lockfile resolution; the few legitimate consumers (``node-gyp``-based native modules) should be allow-listed via a follow-up ``npm rebuild <pkg> --ignore-scripts=false`` line scoped to the specific package.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DF-025: RUN writes a registry auth token into a Docker layer { #df-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Fires when a ``RUN`` body writes a recognized registry-auth token line into a file via ``echo`` / ``printf`` / heredoc. Patterns matched: ``//registry.npmjs.org/:_authToken=`` (and any ``//host/:_authToken=`` shape), ``//host/:_password=``, ``//host/:_auth=`` (npm legacy basic auth), and the pip equivalents ``index-url = https://<user>:<pass>@host`` and ``extra-index-url = https://<user>:<pass>@host``. Token value may be a literal or a ``$VAR`` / ``${VAR}`` interpolation, both end up in the layer once the build args / env are substituted. Complements DF-019 (``COPY`` of a ``.npmrc`` from the build context); DF-025 catches the in-layer write that DF-019 can't see.

**Known false-positive modes**

- An interpolation that references an env var the Dockerfile intentionally leaves unset at build time (placeholder line for a templated install script) still triggers the rule; the regex can't reason about whether ``$NPM_TOKEN`` resolves to anything. Either remove the line entirely or move to a ``--mount=type=secret`` flow.

**Seen in the wild**

- Numerous public Docker Hub leaks of ``_authToken=`` lines in image layers (search ``//registry.npmjs.org/:_authToken`` on public registries). The same lateral-movement primitive the Shai-Hulud worm relies on: any stolen NPM token reaches the victim's publish-scope packages on the next ``npm publish``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't bake registry tokens into layers. Use BuildKit secret mounts: ``RUN --mount=type=secret,id=npm,target=/root/.npmrc npm ci`` (the file is mounted only for the duration of the step and never lands in the image). For pip, mount a ``pip.conf`` the same way, or use ``--mount=type=secret`` to expose ``PIP_INDEX_URL`` containing the credentials. A secret written into a layer is recoverable from the image with ``docker save`` + ``tar``, even if a later ``RUN`` deletes the file.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-026: ENV disables Node.js TLS certificate verification { #df-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on any ``ENV NODE_TLS_REJECT_UNAUTHORIZED=`` value that resolves to ``0`` (or the string ``"0"``). The documented Node.js mechanism for disabling TLS verification, applies to every TLS socket the runtime opens for the rest of the image's life. ``ENV ... =1`` (re-enable) and ``ENV ... =`` (clear) pass. The same primitive shows up in npm postinstall logs whenever a dep tries to fetch over a network the runner can't verify; once the env is set, the failure mode that caught the bad cert is gone.

**Known false-positive modes**

- Test-only images that interact with a local mock server using a throwaway self-signed cert sometimes set this intentionally. Keep the bypass scoped to a separate ``test`` build stage and DON'T copy it into the final image; the production stage should never carry the variable. Suppress on the test-stage Dockerfile with a rationale that names the mock server.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` instruction. The variable tells Node's TLS layer to accept any certificate the upstream presents — self-signed, expired, hostname-mismatched, attacker-presented. Anything baked into ``ENV`` applies to every Node process the image ever launches: ``npm install``, ``npm publish``, runtime fetch calls, postinstall scripts. The attacker doesn't need to compromise the registry — they only need to MITM the network path between the container and any HTTPS endpoint.

If the internal registry / API genuinely has a self-signed cert, install the CA into the image's truststore instead: ``COPY ca.crt /usr/local/share/ca-certificates/`` + ``RUN update-ca-certificates`` (Debian) or ``RUN cat ca.crt >> /etc/ssl/certs/ca-certificates.crt`` (Alpine). The CA install is a one-time build cost; the bypass is a permanent runtime liability.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-027: ENV disables Python HTTPS certificate verification { #df-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on ``ENV PYTHONHTTPSVERIFY=0`` (also the stringy ``"0"``). The variable is the documented Python mechanism for disabling stdlib HTTPS verification; once set in the image ENV, every ``urllib``-based TLS connection (and the libraries that delegate to it) accept any certificate.

Complements DF-021 (``pip install`` TLS bypass via flags) and DF-026 (Node TLS bypass via env). Together the three cover the same primitive shape across pip-flag, Node-env, and Python-env surfaces.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``ENV PYTHONHTTPSVERIFY=0`` instruction. The variable tells Python's stdlib ``urllib`` and any library that delegates to it (most of them) to accept any TLS certificate. The bypass applies to every subsequent process — ``pip install``, runtime API calls, postinstall scripts — for the rest of the image's life. The same primitive in flag form (``pip install --trusted-host``) is DF-021's surface; DF-027 catches the env-var form that affects every Python invocation, not just pip.

If the internal index has a self-signed cert, install the CA into the image's truststore (``REQUESTS_CA_BUNDLE`` pointing at a real CA bundle, or ``update-ca-certificates`` for the system bundle) rather than blanket-disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-028: ENV disables Git TLS certificate verification { #df-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires on ``ENV GIT_SSL_NO_VERIFY`` set to any truthy value (``1``, ``true``, ``yes``, ``on``). The documented Git mechanism for disabling SSL verification per-process; in ``ENV`` form, every Git operation the image runs (and every downstream tool that shells out to ``git``) sees the bypass.

Pairs with DF-026 (Node TLS), DF-027 (Python TLS), and DF-029 (Python requests TLS) for the env-var-based TLS-bypass surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``ENV GIT_SSL_NO_VERIFY`` instruction (or set it to ``0`` / unset it explicitly). The variable tells every ``git clone`` / ``git fetch`` / ``git pull`` in the image to accept any TLS certificate the upstream presents. Baked into ``ENV`` it applies to:

* ``RUN git clone`` in subsequent build stages
* ``git+https://...`` deps that pip / npm / cargo / go   modules clone at install time
* Any runtime process that shells out to ``git``   (release-publishing scripts, mirror jobs, GitOps   agents reading from the image)

If you need to clone from an internal Git server with a self-signed cert, install the CA into the image's truststore — same fix as DF-026 / DF-027. The TLS-bypass primitive doesn't need to be image-wide for any legitimate use case.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-029: ENV neuters Python requests CA bundle { #df-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Fires when ``ENV REQUESTS_CA_BUNDLE`` resolves to a value that disables verification:

* ``/dev/null`` (literal),
* the empty string (``ENV REQUESTS_CA_BUNDLE=`` or   ``ENV REQUESTS_CA_BUNDLE=""``),
* whitespace-only values.

A path to a real file (``/etc/ssl/certs/...``, ``/usr/local/share/ca-certificates/internal.crt``) passes — the rule only flags the disable shapes. Pairs with DF-027 (Python TLS via env).

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``ENV REQUESTS_CA_BUNDLE`` to the path of a real CA bundle (typically ``/etc/ssl/certs/ca-certificates.crt`` on Debian or ``/etc/ssl/cert.pem`` on Alpine), or unset it entirely so the ``requests`` library falls back to ``certifi``. Pointing the variable at ``/dev/null`` or an empty string is a documented anti-pattern: ``requests`` treats the empty / missing bundle as 'verify against nothing,' which silently accepts every certificate.

The same shape as DF-027 (``PYTHONHTTPSVERIFY=0``) but narrower in surface — ``REQUESTS_CA_BUNDLE`` only affects ``requests`` and its descendants, not the stdlib ``urllib``. Still a real bypass because most Python network clients (pip, AWS CLI, Anchore, Trivy, every Django app) flow through ``requests``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DF-030: ENV NODE_OPTIONS preloads code or opens an inspector { #df-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-489</span>
</div>

Fires when ``ENV NODE_OPTIONS`` contains any of:

* ``--require=<path>`` / ``--require <path>`` /   ``-r <path>`` (the short alias Node accepts inside   ``NODE_OPTIONS``), or ``--import=<path>`` /   ``--import <path>``   (preload a module on every Node startup)
* ``--inspect`` / ``--inspect=...`` /   ``--inspect-brk`` (open V8 inspector port)

Safe flags (``--max-old-space-size=``, ``--enable-source-maps``, ``--unhandled-rejections=throw``, etc.) pass. The rule flags the *primitive*, not the value — even an innocent-looking ``--require=./preload.js`` is the same shape as the malicious one, and the security decision is at the build-policy layer.

**Known false-positive modes**

- Sanitizer / APM / coverage tools sometimes legitimately use ``--require`` to inject their agent. Suppress with a rationale that names the specific agent and the path to its module. The rule deliberately flags the pattern because the same shape is the runtime-injection primitive Shai-Hulud-class npm worms exploit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``--require=`` / ``--import=`` and ``--inspect`` / ``--inspect-brk`` flags from ``NODE_OPTIONS``. Each is a runtime-injection or remote-debugger primitive baked into every ``node`` invocation the image runs:

* ``--require=<module>`` and ``--import=<module>``   preload a module before user code runs. The Node   equivalent of ``LD_PRELOAD`` (DF-023): any process   that can drop a file in the image's filesystem can   inject that module's side effects into every Node   process.
* ``--inspect`` / ``--inspect-brk`` opens the V8   inspector on port 9229 (or the configured port).   Anyone who can reach that port has full debugger   control: read process memory (incl. secrets), set   breakpoints, and execute arbitrary code in the   Node context.

If your image needs an APM-style preload (Datadog, Sentry, OpenTelemetry), scope it to the specific service entrypoint via the agent's own startup wrapper rather than baking it into ``ENV NODE_OPTIONS``. The image-wide form applies to every Node process — including ``npm`` and ``yarn`` themselves — which broadens the attack surface unnecessarily.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DF-031: COPY --from external image not pinned to sha256 digest { #df-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires when a ``COPY`` / ``ADD`` carries ``--from=<X>`` where ``X`` is an external image reference (it contains a registry / tag / digest separator and does not match an earlier ``FROM ... AS <stage>`` name or a numeric stage index) and ``X`` is not ``@sha256:``-pinned. DF-001 only inspects ``FROM``, so an unpinned ``COPY --from=<image>`` (a common way to pull ``cosign`` / ``kubectl`` / a CA bundle into the build) sidesteps it entirely. Reuses ``_primitives/image_pinning.classify`` so a floating tag and a pinned-but-mutable tag are both treated as unpinned, matching DF-001. A ``--from=<stage>`` (a named or numbered build stage) and a bare build-context name are not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the image in ``COPY --from=<image>`` (and ``ADD --from=<image>``) to an immutable ``@sha256:<digest>``, the same way DF-001 requires for ``FROM``. A ``--from`` that names an external image (not an earlier ``FROM ... AS <stage>``) pulls that image at build time and copies bytes out of it, so a floating tag lets the registry serve different content under the same reference, and a typosquatted / taken-over name ships an attacker's binary straight into the final image. Resolve the digest (``docker buildx imagetools inspect <ref>``) and let Renovate / Dependabot refresh it. For first-party content, copy from a named build stage instead.

</div>

</div>

---

## Adding a new Dockerfile check

1. Create a new module at
   `pipeline_check/core/checks/dockerfile/rules/dfNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
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
