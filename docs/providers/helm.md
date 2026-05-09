# Helm chart provider

Renders Helm charts via `helm template` and runs the [Kubernetes
provider's](kubernetes.md) 35-rule pack against the resulting
manifests, plus a small chart-supply-chain rule pack
(`HELM-001`--`003`) that reads `Chart.yaml` and `Chart.lock`
straight off disk. The K8s pass scores rendered workloads
(securityContext, hostPath, RBAC, …); the HELM pass scores the
chart's own posture (legacy schema, lockfile drift, plaintext
dependency repos).

Most production Kubernetes ships through Helm, so a chart-aware
front-end means today's K8S-* rules finally see the bulk of real
workloads instead of the hand-written manifests that happen to land
in `k8s/`. Findings from the K8s pass carry the source-template path
(e.g. `mychart/templates/deployment.yaml`) so a "privileged
container" finding points at the actual template file, not the
rendered output.

## Requirements

- **`helm` (Helm 3) on PATH.** The provider shells out to `helm
  template`. Helm 2 is rejected on probe. It has been EOL since
  November 2020. Install instructions:
  [helm.sh/docs/intro/install](https://helm.sh/docs/intro/install/).
- **Chart dependencies pre-resolved.** If your chart declares
  dependencies in `Chart.yaml`, run `helm dependency update` first.
  The provider does not fetch dependencies for you (network access
  during scanning is out of scope for the static-analysis posture
  the tool keeps everywhere else).

## Producer workflow

```bash
# --helm-path is auto-detected when Chart.yaml exists at cwd, or
# when a charts/ directory holds one or more sub-charts.
pipeline_check --pipeline helm

# …or pass it explicitly. Either a single chart directory or a
# packaged chart .tgz works.
pipeline_check --pipeline helm --helm-path ./charts/myapp
pipeline_check --pipeline helm --helm-path ./dist/myapp-1.2.3.tgz

# A parent directory containing multiple charts renders each one
# (one Chart.yaml per immediate subdirectory). Vendored
# dependencies under <chart>/charts/ are not double-rendered.
pipeline_check --pipeline helm --helm-path ./charts/
```

### Values and overrides

`--helm-values` and `--helm-set` map straight onto `helm template -f`
and `helm template --set`. Repeat each flag for multiple values:

```bash
pipeline_check --pipeline helm --helm-path ./mychart \
    --helm-values values-prod.yaml \
    --helm-values values-prod-overrides.yaml \
    --helm-set image.tag=v1.2.3 \
    --helm-set replicas=3
```

Precedence matches Helm's: later `-f` files override earlier ones,
and `--set` overrides files. The chart's own `values.yaml` is
applied automatically by Helm; you don't need to pass it.

Scanning a chart with the **production** values is usually what you
want, a chart that only exposes a `privileged: true` workload when
`debug: true` is set should not fail the gate during routine
scanning.

## What it covers

### Rendered-manifest rules (30)

The same 35 K8S-* rules listed on the [Kubernetes provider
page](kubernetes.md). Every one of them, `securityContext`,
`hostPath`, RBAC blast radius, Secret hygiene, control-plane
scheduling, applies to rendered chart output identically. The
rules see the manifest output of `helm template`, so values-driven
toggles and conditional templates are scored as they would actually
deploy.

### Chart-supply-chain rules (10)

Ten rules score the chart's own packaging metadata, read straight
off `Chart.yaml` / `Chart.lock` rather than the rendered output:

- **HELM-001: Legacy `apiVersion: v1`** (MEDIUM). v1 is Helm 2's
  chart format. Helm 3 still renders it but the shape predates
  `Chart.lock` and inlined dependencies, so HELM-002 can't get
  traction until the chart is bumped to `v2`. Fix by editing
  `Chart.yaml` and re-running `helm dependency update` to
  regenerate the lock against the new shape. `--fix` drops a
  comment-only TODO above the offending line.
- **HELM-002: Missing or incomplete `Chart.lock`** (HIGH). A
  `v2` chart that declares `dependencies:` but ships no
  `Chart.lock`, ships a lock missing entries the manifest declares,
  or ships entries without a `sha256:` digest. Each of those leaves
  `helm dependency build` free to pull a different tarball under
  the same version. Fix by re-running `helm dependency update`
  after every change to `dependencies:` and committing the
  regenerated lock. `--fix` drops a comment-only TODO above the
  `dependencies:` key.
- **HELM-003: Non-HTTPS dependency repository** (HIGH). Walks
  `dependencies[].repository` and rejects `http://`, `git://`,
  `ftp://`, and other plaintext schemes. Accepted shapes are
  `https://` (chart-museum / OSS chart repos), `oci://` (registry-
  hosted charts pulled over TLS), `file://` (in-repo dependency),
  and `@alias` (a local `helm repo add`-registered name). Plaintext
  fetch lets any on-path attacker swap the dependency tarball
  before HELM-002's digest catches it on the *next* update.
  `--fix` drops a comment-only TODO above each offending repository
  line.
- **HELM-004: Dependency version is a range, not a pin** (MEDIUM).
  `dependencies[].version` accepts the full SemVer range syntax
  (`^1.2.3`, `~1.2`, `>=1.2 <2`, `*`, `1.x`). Range constraints
  let `helm dependency update` move every consumer to a different
  version on the next refresh, even with a stable lock. Exact pins
  (`17.0.0`, `v1.2.3`, optionally with pre-release / build
  metadata) eliminate that drift.
- **HELM-005: Maintainers field empty or missing chain-of-custody**
  (LOW). `maintainers:` is the chart's chain-of-custody record. An
  entry needs a non-empty `name` plus either `email` or `url` to be
  considered usable. A chart published without it is anonymous to
  downstream consumers, fine for a personal scratch chart, not for
  one shipped through a CI pipeline.
- **HELM-006: `kubeVersion` compatibility range absent** (LOW).
  Helm refuses `helm install` when the cluster's reported version
  falls outside the chart's declared `kubeVersion` SemVer range,
  catching silent-breakage surprises (removed apiVersions, renamed
  RBAC verbs, alpha features). Charts shipped without the field will
  install against any cluster, including ones whose removed APIs the
  chart still emits.
- **HELM-007: Chart description empty** (LOW). The `description:`
  field is what Helm registries display in chart listings.
  Without it, the chart shows up as a bare name with no hint at
  what it deploys, discovery and trust both suffer.
- **HELM-008: `Chart.lock` generated > 90 days ago** (MEDIUM).
  Stale `Chart.lock` means `helm dependency update` hasn't been
  run in a while; CVE fixes and deprecation notices from the last
  quarter haven't been considered. The 90-day threshold is the
  same cadence CIS / NIST use for credential rotation.
- **HELM-009: Chart `home` / `sources` non-HTTPS** (LOW). The
  chart's landing-page and source-repository URLs displayed by
  registries should be HTTPS. Plaintext URLs let an on-path
  attacker rewrite the page (or 301 to a typo-squat) for anyone
  evaluating the chart's provenance.
- **HELM-010: Chart `appVersion` empty** (LOW). `appVersion` is
  the version of the application packaged in the chart, distinct
  from `version:` (which is the chart's own version). Without it,
  CVE tracking against the upstream application has no anchor,
  `helm list` shows `-` in the AppVersion column. Library charts
  (`type: library`) are exempted.

These rules ride on the same `Chart` records the provider parses
once at scan start, so they don't pay the helm-render cost a second
time. They run regardless of whether the rendered manifests scored
clean, a chart can have a perfect `securityContext` posture and
still ship a v1 schema, an unlocked dependency, or no maintainers.

## What it can't see

`helm template` renders charts against a synthetic release context.
A few constructs aren't represented faithfully:

- **`.Capabilities.APIVersions`** renders against Helm's default
  capability set, not your real cluster. Charts that conditionally
  emit a `NetworkPolicy` only when the `networking.k8s.io/v1` API
  is present will render assuming it is.
- **`lookup`** functions return empty maps: there's no cluster
  to query, so resources gated on a live `lookup` won't render.
- **Hooks** (`helm.sh/hook` annotations) render like any other
  manifest. K8S-* rules apply to them equally; this is the right
  call because a privileged hook pod is just as dangerous as a
  privileged long-lived workload.
- **Library charts** (`Chart.yaml` `type: library`) produce no
  output and are skipped with an info-level warning.

The render context uses synthetic `.Release.Name = "pipeline-check"`
and `.Release.Namespace = "default"`. Templates that hardcode
namespace logic against `.Release.Namespace` see `default` and
behave accordingly.

## Render failures

If `helm template` exits non-zero, bad template syntax, undefined
values, missing dependency, the chart is recorded in
`ctx.warnings` and skipped. Other charts in the same scan continue
to render. The first non-empty stderr line is surfaced so the user
can find the template error without re-running helm by hand.

## Source attribution

`helm template` injects `# Source: <chart>/templates/<file>.yaml`
above each rendered document. The provider parses these and
attaches the chart-relative template path to the parsed manifest,
which surfaces in:

- the inventory output (`source` column points at the template
  file, not the synthetic `<rendered>` path)
- the Kubernetes manifest's display string used by reporters
- the `Manifest.source_template` field exposed via the public
  Python API

Per-finding location attribution at the line level is a separate
concern that affects the K8s rule pack as a whole; in this
release, finding offenders are listed by `Kind/name` and the
template file shows up in inventory.
