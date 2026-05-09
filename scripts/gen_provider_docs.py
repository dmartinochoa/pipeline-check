"""Generate provider reference documentation from the rule registry.

Before this existed, ``docs/providers/<provider>.md`` was a
hand-maintained markdown file that duplicated rule metadata
(check IDs, titles, severities, recommendations) already declared
in Python. The parallel state rotted: a new check meant edits in
three places (the check class, the standards mapping, and the doc)
and any of them could drift.

With the per-rule-module refactor (see
``pipeline_check/core/checks/<provider>/rules/``), every rule
exports a ``RULE`` object carrying its metadata plus prose fields
(``recommendation``, ``docs_note``). This script walks that
registry and writes a fully-derived provider doc, the code is
the source of truth and the doc can never drift.

Usage
-----
    python scripts/gen_provider_docs.py           # write every supported provider
    python scripts/gen_provider_docs.py github    # write just one provider

The supported provider list is enumerated by ``SUPPORTED_PROVIDERS``
below; pass ``--help`` to a fresh checkout to see the current set.
"""
from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

# Make ``pipeline_check`` importable when the script is run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from pipeline_check.core.autofix import _FIXERS
from pipeline_check.core.checks.rule import Rule, discover_rules

#: Set of check_ids that have a registered autofix patch. Read once
#: at module import; the rule-section renderer flips a "🔧 autofix"
#: badge on for rules in this set so users skimming a provider page
#: can see at a glance which findings ``pipeline_check --fix`` will
#: patch automatically vs which need manual remediation.
_AUTOFIXABLE: frozenset[str] = frozenset(_FIXERS.keys())

# ``provider_slug -> (display_title, rules_package_fqn, docs_output_path,
#                     per-provider header markdown)``
SUPPORTED_PROVIDERS: dict[str, tuple[str, str, Path, str]] = {
    "github": (
        "GitHub Actions",
        "pipeline_check.core.checks.github.rules",
        _REPO_ROOT / "docs" / "providers" / "github.md",
        """\
# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory. No
GitHub API token or installed Actions runner is required by default;
the scanner stays read-from-disk-only unless `--resolve-remote` opts
in to fetching reusable-workflow callees over HTTPS.

## Producer workflow

```bash
# --gha-path is auto-detected when .github/workflows exists at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline github

# …or pass it explicitly.
pipeline_check --pipeline github --gha-path .github/workflows
```

A single workflow file can also be passed directly:

```bash
pipeline_check --pipeline github --gha-path .github/workflows/release.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS and Terraform providers.

## Reusable workflow resolution

`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>` references
a workflow body that runs with the *caller's* `GITHUB_TOKEN` and
secrets. By default the scanner stops at the call site (it flags the
ref via `GHA-025` when unpinned and emits a one-line nudge listing
how many remote refs were skipped); `--resolve-remote` opts in to
fetching the called body and running the full GHA rule pack against
it with the caller's permissions context.

```bash
# Fetch via raw.githubusercontent.com (works for public repos).
pipeline_check --pipeline github --resolve-remote

# Private callees: pass a token, or set $GITHUB_TOKEN.
pipeline_check --pipeline github --resolve-remote --gh-token "$GH_PAT"

# Fully offline: search a sibling on-disk checkout instead.
pipeline_check --pipeline github --resolve-remote \\
    --gha-search-path ../shared-workflows
```

Resolution rules:

- **Only SHA-pinned refs are fetched.** A tag-pinned ref (`@v1`,
  `@main`) is skipped with a warning, resolution against a movable
  upstream tag would defeat `GHA-025`'s value.
- **Recursion** follows transitive `uses:` calls to a depth of 3
  (configurable with `--gha-resolve-depth`; hard ceiling 10). Cycles
  are detected.
- **Cache.** Fetched bodies live under
  `~/.cache/pipeline-check/gha-resolver/` for 7 days. Use `--no-cache`
  to bypass.
- **Failure mode.** Network errors, 404s, and malformed YAML never
  abort the scan. They land in the context's warnings stream.
- **Attribution.** Findings on a resolved callee carry a synthetic
  `<caller-path> -> <owner>/<repo>/<path>@<ref>` resource string so
  the report points at both the call site and the upstream body.
- **Permissions inheritance.** A callee without its own
  `permissions:` runs with the caller's; `GHA-004` doesn't fire on a
  callee whose caller declared one.
- **`secrets: inherit`.** When the call site passes
  `secrets: inherit`, `GHA-019` annotates findings with the inherit
  note so report readers see the full credential surface.
""",
    ),
    "gitlab": (
        "GitLab CI",
        "pipeline_check.core.checks.gitlab.rules",
        _REPO_ROOT / "docs" / "providers" / "gitlab.md",
        """\
# GitLab CI provider

Parses `.gitlab-ci.yml` on disk, no GitLab API token, no runner install.
Works against the file in a detached clone or a merged-result pipeline
export.

## Producer workflow

```bash
# --gitlab-path auto-detected when .gitlab-ci.yml exists at cwd.
pipeline_check --pipeline gitlab

# …or pass it explicitly (file or directory).
pipeline_check --pipeline gitlab --gitlab-path ci/
```
""",
    ),
    "bitbucket": (
        "Bitbucket Pipelines",
        "pipeline_check.core.checks.bitbucket.rules",
        _REPO_ROOT / "docs" / "providers" / "bitbucket.md",
        """\
# Bitbucket Pipelines provider

Parses `bitbucket-pipelines.yml` on disk, no Bitbucket API token, no
runner install.

## Producer workflow

```bash
# --bitbucket-path auto-detected when bitbucket-pipelines.yml exists at cwd.
pipeline_check --pipeline bitbucket

# …or pass it explicitly (file or directory).
pipeline_check --pipeline bitbucket --bitbucket-path ci/
```
""",
    ),
    "azure": (
        "Azure DevOps Pipelines",
        "pipeline_check.core.checks.azure.rules",
        _REPO_ROOT / "docs" / "providers" / "azure.md",
        """\
# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk, no network calls, no ADO
personal access token.

## Producer workflow

```bash
# --azure-path is auto-detected when azure-pipelines.yml is present at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline azure

# …or pass it explicitly.
pipeline_check --pipeline azure --azure-path azure-pipelines.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Shape coverage

The walker handles every layout ADO supports:

- Flat single-job pipeline, top-level `steps:`
- Single-stage multi-job, top-level `jobs:`
- Multi-stage, `stages: → jobs: → steps:`
- Deployment jobs, steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.
""",
    ),
    "jenkins": (
        "Jenkins",
        "pipeline_check.core.checks.jenkins.rules",
        _REPO_ROOT / "docs" / "providers" / "jenkins.md",
        """\
# Jenkins provider

Parses Jenkinsfile text. Declarative or Scripted Pipeline, without
talking to a Jenkins controller. No Groovy interpreter, no plugin
install, no API token.

## Producer workflow

```bash
# --jenkinsfile-path is auto-detected when ./Jenkinsfile exists at cwd.
pipeline_check --pipeline jenkins

# …or pass it explicitly.
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile

# Scan a directory of multiple Jenkinsfiles (e.g. monorepo with per-app pipelines).
pipeline_check --pipeline jenkins --jenkinsfile-path ci/
```

The loader recognises files named `Jenkinsfile` exactly, plus anything
ending in `.jenkinsfile` or `.groovy`. It treats every file as text,
no Groovy parsing, and applies the same regex-driven heuristics the
other workflow providers use for `run:` blocks. False positives are
intentional: better to flag and let the operator suppress than to
miss a real injection because the parser couldn't follow a dynamic
expression.
""",
    ),
    "circleci": (
        "CircleCI",
        "pipeline_check.core.checks.circleci.rules",
        _REPO_ROOT / "docs" / "providers" / "circleci.md",
        """\
# CircleCI provider

Parses `.circleci/config.yml` on disk, no CircleCI API token, no
runner install.

## Producer workflow

```bash
# --circleci-path is auto-detected when .circleci/config.yml exists at cwd.
pipeline_check --pipeline circleci

# …or pass it explicitly.
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### CircleCI-specific checks

Several checks target CircleCI concepts that have no direct analogue
in other providers:

- **CC-001**, orb version pinning (`@volatile`, `@1` → `@5.1.0`)
- **CC-009**, approval gate via `type: approval` predecessor job
- **CC-012**, dynamic config generation via `setup: true`
- **CC-019**, `add_ssh_keys` fingerprint restriction
""",
    ),
    "cloudbuild": (
        "Google Cloud Build",
        "pipeline_check.core.checks.cloudbuild.rules",
        _REPO_ROOT / "docs" / "providers" / "cloudbuild.md",
        """\
# Google Cloud Build provider

Parses `cloudbuild.yaml` on disk, no Google Cloud credentials, no
`gcloud` install, no Cloud Build API token required. Each document
must declare a top-level `steps:` list; files without it (SAM
templates, ordinary YAML configs) are skipped by the loader.

## Producer workflow

```bash
# --cloudbuild-path is auto-detected when cloudbuild.yaml/cloudbuild.yml
# exists at cwd.
pipeline_check --pipeline cloudbuild

# …or pass it explicitly.
pipeline_check --pipeline cloudbuild --cloudbuild-path ci/cloudbuild.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Cloud Build-specific checks

Several checks target Cloud Build concepts that have no direct
analogue in other providers:

- **GCB-002**, `serviceAccount:` must be set; the default Cloud Build
  SA is typically broader than any single pipeline needs.
- **GCB-003**, secrets must flow through `availableSecrets.secret
  Manager[].env` + `secretEnv:`, never via inline `gcloud secrets
  versions access` in `args`.
- **GCB-004**, `options.dynamicSubstitutions: true` combined with a
  user-substitution (`$_FOO`) in step args opens a trigger-editor-
  controlled shell-injection path.
""",
    ),
    "kubernetes": (
        "Kubernetes",
        "pipeline_check.core.checks.kubernetes.rules",
        _REPO_ROOT / "docs" / "providers" / "kubernetes.md",
        """\
# Kubernetes manifest provider

Parses Kubernetes API documents (`apiVersion:` + `kind:`) from `.yaml`
/ `.yml` files on disk, text-only static analysis. No `kubectl`, no
cluster access, no Helm or Kustomize rendering. Multi-document YAML
(`---`-separated) is fully supported; each document is parsed into
its own `Manifest` record.

Helm chart values, kustomization base files, and other YAML that
doesn't carry the canonical `apiVersion` + `kind` shape are silently
skipped, so a directory mixing manifests with `Chart.yaml` /
`values.yaml` / `kustomization.yaml` won't trip the loader.

## Producer workflow

```bash
# --k8s-path is auto-detected when ./kubernetes/, ./k8s/, or
# ./manifests/ exist at cwd.
pipeline_check --pipeline kubernetes

# …or pass it explicitly (file or directory).
pipeline_check --pipeline kubernetes --k8s-path k8s/

# A single multi-document manifest works too.
pipeline_check --pipeline kubernetes --k8s-path deploy.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Workload coverage

The walker recognises every kind that carries a pod spec:

- `Pod`, pod spec at `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job`
 , pod spec at `spec.template.spec`
- `CronJob`, pod spec at `spec.jobTemplate.spec.template.spec`

Container-level rules walk all three container lists (`containers`,
`initContainers`, `ephemeralContainers`), so init-time and ephemeral
debug containers are covered along with the long-lived workload.

### RBAC and Service rules

Four rules target non-workload kinds:

- **K8S-018**, `Kind: Secret` carrying credential-shaped literals
  in `stringData` or `data`. Base64 values in `data:` are decoded
  and re-checked for AKIA-shaped AWS keys.
- **K8S-020**, `ClusterRoleBinding` to `cluster-admin`, `admin`,
  or `system:masters`.
- **K8S-021**, `Role` / `ClusterRole` granting wildcard verbs+
  resources (both `verbs: ["*"]` and `resources: ["*"]`).
- **K8S-022**, `Service` exposing port 22 (SSH).
""",
    ),
    "buildkite": (
        "Buildkite",
        "pipeline_check.core.checks.buildkite.rules",
        _REPO_ROOT / "docs" / "providers" / "buildkite.md",
        """\
# Buildkite provider

Parses `.buildkite/pipeline.yml` (or any user-named pipeline file) on
disk, no Buildkite API token, no agent install required. Each
document must declare a top-level `steps:` list; files without it are
skipped by the loader.

## Producer workflow

```bash
# --buildkite-path is auto-detected when .buildkite/pipeline.yml
# exists at cwd.
pipeline_check --pipeline buildkite

# …or pass it explicitly.
pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Buildkite-specific checks

- **BK-001**, plugin refs must be pinned to an exact tag
  (`docker-compose#v4.13.0`) or a 40-char SHA. Branch refs (`#main`)
  and bare names float and let a compromised plugin release execute
  in the pipeline.
- **BK-007**, every step that looks like a deploy (label / command
  matches `deploy`, `kubectl apply`, `terraform apply`, `helm
  upgrade`, …) must be preceded by a `block:` or `input:` step in
  the same pipeline file. Buildkite waits for a human to click
  *Unblock* before the gated steps run.
""",
    ),
    "tekton": (
        "Tekton",
        "pipeline_check.core.checks.tekton.rules",
        _REPO_ROOT / "docs" / "providers" / "tekton.md",
        """\
# Tekton provider

Parses Tekton API documents (`apiVersion: tekton.dev/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `tkn` binary,
no cluster access. Recognized kinds: `Task`, `ClusterTask`,
`Pipeline`, `TaskRun`, `PipelineRun`. Documents that don't carry a
`tekton.dev/*` apiVersion are silently skipped, so a directory mixing
Tekton with plain Kubernetes manifests is safe to point at.

## Producer workflow

```bash
pipeline_check --pipeline tekton --tekton-path tekton/

# A single multi-document file works too.
pipeline_check --pipeline tekton --tekton-path tekton/build-task.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Tekton-specific checks

- **TKN-003**. Tekton substitutes `$(params.X)` *before* the shell
  parses the script, so any unquoted use is a command-injection
  primitive. The safe pattern is to receive the parameter through
  `env:` and reference the env var quoted (`"$NAME"`).
- **TKN-007**, `TaskRun` / `PipelineRun` must set
  `serviceAccountName` to a least-privilege ServiceAccount. The
  default SA inherits whatever cluster-admin or wildcard role
  someone later binds to it.
""",
    ),
    "argo": (
        "Argo Workflows",
        "pipeline_check.core.checks.argo.rules",
        _REPO_ROOT / "docs" / "providers" / "argo.md",
        """\
# Argo Workflows provider

Parses Argo API documents (`apiVersion: argoproj.io/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `argo` binary,
no cluster access. Recognized kinds: `Workflow`, `WorkflowTemplate`,
`ClusterWorkflowTemplate`, `CronWorkflow`. Documents that don't
carry an `argoproj.io/*` apiVersion are silently skipped.

## Producer workflow

```bash
pipeline_check --pipeline argo --argo-path workflows/

# A single workflow file works too.
pipeline_check --pipeline argo --argo-path workflows/release.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Argo-specific checks

- **ARGO-005**, `{{inputs.parameters.X}}` substitution happens
  before the shell parses the script, so any unquoted use in
  `script.source` / `container.args` is a command-injection
  primitive. Pass the parameter via `env:` and reference quoted.
- **ARGO-003**, `Workflow` / `CronWorkflow` must set
  `serviceAccountName`. Workflows that fall back to the namespace's
  `default` SA inherit whatever role someone later binds to
  `default`.
""",
    ),
    "drone": (
        "Drone CI",
        "pipeline_check.core.checks.drone.rules",
        _REPO_ROOT / "docs" / "providers" / "drone.md",
        """\
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
""",
    ),
    "oci": (
        "OCI image manifest",
        "pipeline_check.core.checks.oci.rules",
        _REPO_ROOT / "docs" / "providers" / "oci.md",
        """\
# OCI image manifest provider

Parses OCI image manifests / image-indexes from disk, pure JSON, no
registry pull, no image build, no daemon access. The user captures
the manifest with ``docker buildx imagetools inspect --raw <ref>``
(or the equivalent ``oras manifest fetch`` / ``crane manifest``)
and points the scanner at the resulting JSON. Recognized media
types: the OCI 1.0 / 1.1 spec types
(``application/vnd.oci.image.{index,manifest}.v1+json``) and the
Docker-distribution-v2 equivalents BuildKit still emits by default.

## Producer workflow

```bash
# Capture the index from a registry into a JSON file.
docker buildx imagetools inspect --raw \\
    ghcr.io/example/app:1.0.0 > image.json

# Run the scanner.
pipeline_check --pipeline oci --oci-manifest image.json

# Or point at a directory; ./index.json is auto-detected.
pipeline_check --pipeline oci --oci-manifest ./oci-layout/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### What the rules expect

OCI rules operate on the manifest *shape* alone, the scanner never
fetches the config blob or layer contents. That keeps the provider
read-from-disk-only and avoids taking on a registry-credential
surface, but it also bounds what's detectable: anything that
requires the config (entrypoint, labels written via
``--label`` rather than ``--annotation``, layer history) is out
of scope. Use the Dockerfile provider in tandem to catch
authoring-time gaps that don't survive into the manifest.

### OCI-specific checks

- **OCI-001**, image manifest must carry
  ``org.opencontainers.image.source`` and
  ``org.opencontainers.image.revision`` annotations. Mirrors
  DF-016 (Dockerfile-time) at the image-manifest layer so a build
  that overrides annotations via ``docker buildx --annotation``
  is still scored.
- **OCI-002**, image index must include at least one attestation
  manifest (BuildKit-style sub-manifest annotated with
  ``vnd.docker.reference.type: attestation-manifest``). This is
  where ``--attest=type=provenance`` and ``--attest=type=sbom``
  land their data; without one, neither SLSA provenance nor an
  SBOM is reachable from the image.
- **OCI-003**, image manifest must carry
  ``org.opencontainers.image.created``. CVE triage uses this to
  determine the image's build date without pulling the config
  blob.
""",
    ),
    "dockerfile": (
        "Dockerfile",
        "pipeline_check.core.checks.dockerfile.rules",
        _REPO_ROOT / "docs" / "providers" / "dockerfile.md",
        """\
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
""",
    ),
}


_FOOTER_TEMPLATE = """\
---

## Adding a new {title} check

1. Create a new module at
   `pipeline_check/core/checks/{pkg}/rules/{prefix_lc}NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `{signature}`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the {arg_kind}.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/{pkg}/{prefix}-NNN.{{unsafe,safe}}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py {slug}
   ```
"""


# Per-provider check signature strings. Tekton and Argo (and other
# context-based providers) hand the rule a typed context; the older
# workflow providers still take ``(path, doc)``.
_DEFAULT_SIGNATURE = "check(path, doc) -> Finding"
_DEFAULT_ARG_KIND = "parsed YAML document"

_FOOTER_CONFIG: dict[str, dict[str, str]] = {
    "github":    {"prefix": "GHA", "prefix_lc": "gha", "pkg": "github"},
    "gitlab":    {"prefix": "GL",  "prefix_lc": "gl",  "pkg": "gitlab"},
    "bitbucket": {"prefix": "BB",  "prefix_lc": "bb",  "pkg": "bitbucket"},
    "azure":     {"prefix": "ADO", "prefix_lc": "ado", "pkg": "azure"},
    "jenkins":   {"prefix": "JF",  "prefix_lc": "jf",  "pkg": "jenkins"},
    "circleci":  {"prefix": "CC",  "prefix_lc": "cc",  "pkg": "circleci"},
    "cloudbuild": {"prefix": "GCB", "prefix_lc": "gcb", "pkg": "cloudbuild"},
    "buildkite": {"prefix": "BK",  "prefix_lc": "bk",  "pkg": "buildkite"},
    "tekton":    {
        "prefix": "TKN", "prefix_lc": "tkn", "pkg": "tekton",
        "signature": "check(ctx: TektonContext) -> Finding",
        "arg_kind": "``TektonContext``",
    },
    "argo":      {
        "prefix": "ARGO", "prefix_lc": "argo", "pkg": "argo",
        "signature": "check(ctx: ArgoContext) -> Finding",
        "arg_kind": "``ArgoContext``",
    },
    "dockerfile": {"prefix": "DF",  "prefix_lc": "df",  "pkg": "dockerfile"},
    "kubernetes": {"prefix": "K8S", "prefix_lc": "k8s", "pkg": "kubernetes"},
    "oci": {
        "prefix": "OCI", "prefix_lc": "oci", "pkg": "oci",
        "signature": "check(manifest: OCIManifest) -> Finding",
        "arg_kind": "``OCIManifest``",
    },
    "drone": {
        "prefix": "DR", "prefix_lc": "dr", "pkg": "drone",
        "signature": "check(pipeline: Pipeline) -> Finding",
        "arg_kind": "``Pipeline``",
    },
}


def _render_provider(title: str, header: str, rules_fqn: str, slug: str = "") -> str:
    """Walk the rule registry and stitch together the full provider doc."""
    pairs = discover_rules(rules_fqn)
    lines: list[str] = [header.rstrip() + "\n\n"]

    # ── Summary table ──
    # Each check ID links to the per-rule section further down via a
    # pinned attr-list anchor (``{ #gha-001 }``) on the rendered H2.
    # The severity column emits a color-coded chip so the table
    # doubles as a click-through priority list. The ``Fix`` column
    # marks rules with a registered autofix patch, useful for
    # filtering with the sortable-table JS layered over markdown
    # tables ("show me all the things ``--fix`` will patch").
    fix_count = sum(1 for r, _ in pairs if r.id in _AUTOFIXABLE)
    lines.append("## What it covers\n\n")
    lines.append(
        f"{len(pairs)} checks · {fix_count} have an autofix patch "
        f"(``--fix``).\n\n"
    )
    lines.append("| Check | Title | Severity | Fix |\n")
    lines.append("|-------|-------|----------|-----|\n")
    for rule, _ in pairs:
        anchor = _rule_anchor(rule.id)
        sev_chip = _severity_chip(rule.severity.value)
        fix_cell = _autofix_chip(rule.id)
        lines.append(
            f"| [{rule.id}](#{anchor}) | {rule.title} | {sev_chip} | {fix_cell} |\n"
        )
    lines.append("\n---\n\n")

    # ── Per-rule section ──
    for rule, _ in pairs:
        lines.append(_render_rule(rule))

    footer_cfg = dict(_FOOTER_CONFIG.get(slug, {"prefix": "", "prefix_lc": "", "pkg": slug}))
    footer_cfg.setdefault("signature", _DEFAULT_SIGNATURE)
    footer_cfg.setdefault("arg_kind", _DEFAULT_ARG_KIND)
    lines.append(_FOOTER_TEMPLATE.format(title=title, slug=slug, **footer_cfg))
    return "".join(lines)


def _rule_anchor(rule_id: str) -> str:
    """Stable in-page anchor for a rule_id.

    Pinned via ``attr_list`` ``{ #gha-001 }`` on the H2, so the slug
    is deterministic regardless of the title text or its punctuation.
    Markdown's default ``toc`` slugifier would strip the em-dash and
    derive the slug from the title, fine, but couples the anchor to
    the wording. A pinned ID survives title rephrases.
    """
    return rule_id.lower()


def _severity_chip(severity: str) -> str:
    """HTML chip used in summary tables. Uses a CSS class per severity
    so the color is theme-aware (different on light vs slate)."""
    sev_lc = severity.lower()
    return f'<span class="pg-sev pg-sev--{sev_lc}">{severity}</span>'


def _autofix_chip(rule_id: str) -> str:
    """A tiny "🔧 fix" badge for rules with a registered autofix.

    Renders as an empty cell when the rule has no fixer, keeps the
    table tidy without spelling out "no". Sortable-tables JS treats
    empty cells as "comes after populated", so sorting by Fix puts
    autofixable rules first.
    """
    if rule_id in _AUTOFIXABLE:
        return '<span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span>'
    return ""


def _render_rule(rule: Rule) -> str:
    """Render one rule as a card-style section with severity rail.

    Output shape (renders in MkDocs' ``md_in_html`` extension; the
    ``markdown`` attribute lets nested markdown inside the
    ``<div>`` cascades work as expected):

        <div class="pg-rule pg-rule--high" markdown>

        ## GHA-001, title { #gha-001 }

        <div class="pg-rule__tags">…severity chip + tag pills…</div>

        Body text (docs_note prose).

        <div class="pg-rule__rec" markdown>
        **Recommended action**
        …recommendation prose…
        </div>

        </div>

    The CSS picks up ``pg-rule--<severity>`` to color the left
    rail, the chip, and the recommendation block accent.
    """
    parts: list[str] = []
    anchor = _rule_anchor(rule.id)
    sev = rule.severity.value
    sev_lc = sev.lower()

    parts.append(f'<div class="pg-rule pg-rule--{sev_lc}" markdown>\n\n')
    parts.append(f"## {rule.id}: {rule.title} {{ #{anchor} }}\n\n")

    # ── Tag chip row: severity + autofix indicator + OWASP + ESF + CWE ──
    chips: list[str] = [_severity_chip(sev)]
    if rule.id in _AUTOFIXABLE:
        chips.append(
            '<span class="pg-fix pg-fix--rule" '
            'title="`--fix` will patch this rule">🔧 autofix</span>'
        )
    for tag in rule.owasp:
        chips.append(f'<span class="pg-tag pg-tag--owasp">{tag}</span>')
    for tag in rule.esf:
        chips.append(f'<span class="pg-tag pg-tag--esf">{tag}</span>')
    for tag in rule.cwe:
        chips.append(f'<span class="pg-tag pg-tag--cwe">{tag}</span>')
    parts.append('<div class="pg-rule__tags">\n')
    parts.append(" ".join(chips) + "\n")
    parts.append("</div>\n\n")

    # ── Body, the rule's ``docs_note`` is the "why this matters"
    # narrative; render as plain prose. ──
    if rule.docs_note:
        parts.append(rule.docs_note.strip() + "\n\n")

    # ── Known-FP modes: surface the same prose ``--explain`` shows so
    # readers see why a rule defaults to LOW / MEDIUM confidence and
    # what kind of legitimate code trips it. Rendered as a bullet list
    # so a multi-mode entry stays scannable. ──
    if rule.known_fp:
        parts.append("**Known false-positive modes**\n\n")
        for mode in rule.known_fp:
            parts.append(f"- {mode.strip()}\n")
        parts.append("\n")

    # ── Recommendation: framed block so it stands out from the body
    # narrative. Marked with ``markdown`` so embedded code blocks /
    # bullet lists in the recommendation render. ──
    if rule.recommendation:
        parts.append('<div class="pg-rule__rec" markdown>\n\n')
        parts.append("**Recommended action**\n\n")
        parts.append(rule.recommendation.strip() + "\n\n")
        parts.append("</div>\n\n")

    parts.append("</div>\n\n")
    return "".join(parts)


def _providers_to_render(argv: Iterable[str]) -> list[str]:
    argv = list(argv)
    if not argv:
        return list(SUPPORTED_PROVIDERS.keys())
    for name in argv:
        if name not in SUPPORTED_PROVIDERS:
            raise SystemExit(
                f"Unknown provider {name!r}. "
                f"Supported: {', '.join(SUPPORTED_PROVIDERS.keys())}"
            )
    return argv


def main(argv: Iterable[str] | None = None) -> None:
    targets = _providers_to_render(argv if argv is not None else sys.argv[1:])
    for slug in targets:
        title, rules_fqn, out_path, header = SUPPORTED_PROVIDERS[slug]
        body = _render_provider(title, header, rules_fqn, slug)
        out_path.write_text(body, encoding="utf-8")
        print(f"[gen-docs] wrote {out_path.relative_to(_REPO_ROOT)} "
              f"({body.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
