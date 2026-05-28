# Helm chart provider

Renders Helm charts via `helm template` and runs the [Kubernetes
provider's](kubernetes.md) full K8S-* rule pack against the resulting
manifests, plus a chart-supply-chain rule pack
(`HELM-001`--`010`) that reads `Chart.yaml` and `Chart.lock`
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
want. A chart that only exposes a `privileged: true` workload when
`debug: true` is set should not fail the gate during routine
scanning.

## Rendered Kubernetes manifests

The full K8S-* rule pack listed on the [Kubernetes provider
page](kubernetes.md) applies to rendered chart output identically
(`securityContext`, `hostPath`, RBAC blast radius, Secret hygiene,
control-plane scheduling). The rules see the manifest output of
`helm template`, so values-driven toggles and conditional templates
are scored as they would actually deploy.

The HELM-* pack below is additive: those rules score the chart's
own packaging metadata, read straight off `Chart.yaml` /
`Chart.lock` rather than the rendered output. A chart can have a
perfect `securityContext` posture and still ship a v1 schema, an
unlocked dependency, or no maintainers.

## What it covers

14 checks · 3 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [HELM-001](#helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HELM-002](#helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HELM-003](#helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [HELM-004](#helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [HELM-005](#helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [HELM-006](#helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [HELM-007](#helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [HELM-008](#helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [HELM-009](#helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [HELM-010](#helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [HELM-011](#helm-011) | Chart dependency repository URL embeds plaintext credentials | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [HELM-012](#helm-012) | Chart marked deprecated without naming a successor | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [HELM-013](#helm-013) | Chart.yaml type field missing or invalid | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [HELM-014](#helm-014) | Chart dependency matches a known-compromised chart registry | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## HELM-001: Chart.yaml declares legacy apiVersion: v1 { #helm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HELM-002: Chart.lock missing per-dependency digests { #helm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Three failure shapes:

1. ``Chart.yaml`` declares dependencies but no ``Chart.lock`` exists at all.
2. ``Chart.lock`` exists but its ``dependencies:`` list is missing entries declared in ``Chart.yaml`` (drift after an edit without re-running ``helm dependency update``).
3. ``Chart.lock`` lists every dependency but one or more entries lack a ``digest:`` field (lock generated by an old Helm 3 version that didn't always populate it).

v1 charts (HELM-001) are skipped. They predate ``Chart.lock`` and use ``requirements.lock`` against a sibling ``requirements.yaml``. Fix HELM-001 first.

**Known false-positive modes**

- Charts with no dependencies (the ``dependencies:`` key is absent or empty) pass automatically. There is nothing to lock.

<div class="pg-rule__rec" markdown>

**Recommended action**

After every change to ``dependencies:`` in ``Chart.yaml``, re-run ``helm dependency update`` and commit the regenerated ``Chart.lock``. The lock records the resolved version *and* a ``sha256:...`` digest that ``helm dependency build`` verifies on download, without it, a compromised chart repo can swap the tarball under the same version and ``helm install`` will happily use the substitute.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HELM-003: Chart dependency declared on a non-HTTPS repository { #helm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## HELM-004: Chart dependency version is a range, not an exact pin { #helm-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## HELM-005: Chart maintainers field empty or missing chain-of-custody info { #helm-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PROV-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

An ``maintainers:`` entry is considered usable when the value is a YAML mapping with ``name:`` set to a non-empty string and at least one of ``email:`` / ``url:`` populated. Entries that look like ``- name: TODO`` or carry blank contact fields fail the rule the same way a missing block does, the field exists but doesn't carry a real chain-of-custody signal.

**Known false-positive modes**

- Library charts (``Chart.yaml`` ``type: library``) often ship without maintainers when distributed inside a single team's monorepo where the org-level CODEOWNERS already names the contact. Suppress with ``--ignore-file`` when this matches your situation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Populate ``maintainers:`` in ``Chart.yaml`` with at least one entry carrying a ``name`` plus either an ``email`` or a ``url``. The ``name`` is the human a downstream consumer files an issue against; the contact field is the channel they reach. Charts published to ArtifactHub or an internal registry without this field are silently anonymous, fine for a personal scratch chart, not for one your CI pipeline will deploy to production.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## HELM-006: Chart.yaml does not declare a kubeVersion compatibility range { #helm-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-COMPAT</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

The field is a string carrying a Helm-flavoured SemVer range. Empty / missing fails the rule. Whitespace-only values fail too, an obviously-blank key should not satisfy a posture check.

**Known false-positive modes**

- Library charts (``Chart.yaml`` ``type: library``) that wrap version-agnostic helpers often legitimately ship without ``kubeVersion``. Suppress with ``--ignore-file`` when the chart genuinely targets every supported Kubernetes minor.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``kubeVersion:`` SemVer range to ``Chart.yaml`` covering the Kubernetes versions you've actually rendered and tested the chart against. ``>= 1.25.0 < 1.32.0`` is the common shape for a chart maintained against the upstream support window. Helm will refuse ``helm install`` against a cluster whose ``kubectl version`` falls outside the range, catching silent-breakage surprises (removed apiVersions, renamed RBAC verbs, alpha features) at pre-flight rather than at runtime.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## HELM-007: Chart.yaml description field is empty or missing { #helm-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PROV-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Walks ``Chart.yaml`` ``description:`` and fires when the field is missing, ``None``, or a string that's empty after stripping whitespace. The Helm chart spec doesn't enforce the field but every chart published to ArtifactHub or the upstream stable repo populates it; production charts that ship without it are usually a copy-paste-from-template oversight.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``description:`` in ``Chart.yaml`` to a one-sentence summary of what the chart deploys (e.g. ``description: Postgres 14 cluster with WAL-G backups and a Prometheus exporter``). Helm registries display this string in chart listings; without it, anyone browsing has to read the README to figure out what the chart does.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## HELM-008: Chart.lock generated more than 90 days ago { #helm-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Reads ``Chart.lock``'s top-level ``generated:`` timestamp (an ISO-8601 string Helm writes when the lock was last regenerated) and compares against ``now``. Fires when the delta is more than 90 days. Charts without ``Chart.lock`` are skipped. HELM-002 covers the missing-lock case directly. Charts whose ``generated:`` field is malformed or absent silently pass on this rule (HELM-002 covers the absent-lock case from a different angle).

**Known false-positive modes**

- A chart that pins exact versions and never needs new dependencies (e.g. a chart packaging a single internal library that itself updates rarely) may legitimately have a stale Chart.lock. Suppress with ``--ignore-file`` when this matches your situation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Run ``helm dependency update`` against every dependency-carrying chart at least once per release cycle, and commit the regenerated ``Chart.lock``. The lock pins versions and digests; the *update cadence* is what brings in CVE fixes and deprecation notices from the last quarter. CI can run the same command against ``main`` weekly to surface drift as a PR rather than letting the lock sit stale until the next release.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## HELM-009: Chart home / sources URL uses a non-HTTPS scheme { #helm-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PROV-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Walks ``Chart.yaml`` ``home:`` (single string) and ``sources:`` (list of strings). Fires on any value whose scheme is ``http://``, ``ftp://``, or other plaintext form. Empty / missing fields pass, the rule only evaluates URLs that are *populated* with the wrong scheme. HELM-003 covers the same risk for dependency-repo URLs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch every ``home:`` URL and every entry in ``sources:`` to ``https://``. Most chart-listing UIs display these as click-through links from a public chart registry; serving them over plaintext is a confused-deputy footgun for anyone evaluating the chart's provenance. ``http://`` URLs against ``localhost`` are not exempted, production charts shouldn't ship references to a developer-local endpoint anyway.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## HELM-010: Chart.yaml appVersion field is empty or missing { #helm-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PROV-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Library charts (``Chart.yaml`` ``type: library``) legitimately don't have an ``appVersion`` because they package no application. Those are exempted. For application charts (``type: application``, the default), ``appVersion`` is required for CVE tracking and release-tracking; without it, ``helm list`` shows ``-`` in the AppVersion column and downstream consumers have no signal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``appVersion:`` in ``Chart.yaml`` to the version of the application the chart packages (e.g. ``appVersion: "17.2"`` for a Postgres-17.2 chart at ``version: 1.4.2``). When the upstream application releases, bump ``appVersion`` and re-cut the chart. Helm's CLI displays ``appVersion`` alongside the chart version in ``helm list``, so downstream operators can see which app version is running where.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HELM-011: Chart dependency repository URL embeds plaintext credentials { #helm-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Reads each ``Chart.yaml`` ``dependencies[].repository`` URL and fires when the authority component carries an ``<user>:<pass>@`` prefix. Empty-password forms (``https://user:@host``) and ``${VAR}`` placeholders are skipped — the former is an operator-flagged 'no credential intended' marker and the latter resolves at fetch time from the environment rather than the manifest text.

Distinct from HELM-003 (non-HTTPS scheme), which catches the transport-side risk. This rule catches the credential-leakage risk: an HTTPS URL with embedded credentials passes HELM-003 cleanly but still leaks the credential into git.

**Known false-positive modes**

- Templated Chart.yaml files that materialize a placeholder credential form (``https://__USER__:__PASS__@host``) and substitute the real value at install time trip this rule by shape. Suppress per dependency when the placeholder marker is stable; the rule's placeholder skip-list only recognizes ``${...}``.

**Seen in the wild**

- Long-running pattern of internal chart-museum credentials leaking through Chart.yaml committed to public mirrors. The credential's audit trail (last rotated, who has it) is lost the moment the file lands in a clone an attacker controls; rotation costs scale with the number of consumers.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential out of the URL and into the consumer's Helm-side credential store. Three stable patterns:

* Add the repo once with credentials: ``helm repo add <name> https://<host>/<path> --username <u> --password <p>``. The credentials land in the user's ``~/.config/helm/repositories.yaml`` (not in the repo) and the chart's ``Chart.yaml`` references the alias (``repository: @<name>``).
* For CI/CD environments, inject credentials at chart-fetch time from environment variables (Helm 3 honors ``HELM_REGISTRY_USERNAME`` / ``HELM_REGISTRY_PASSWORD`` for OCI registries) and keep ``Chart.yaml`` clean.
* For pure HTTPS chart repos, switch to OCI (``repository: oci://<registry>/<repo>``). OCI registries use the standard Docker credential helper chain, so credentials live in ``~/.docker/config.json`` or a managed credential helper, never in Chart.yaml.

Credentials embedded in a committed ``Chart.yaml`` lock the password into git history. Rotation requires consumer-side updates *plus* history scrub before the leaked credential stops being useful to an attacker.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## HELM-012: Chart marked deprecated without naming a successor { #helm-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``Chart.yaml`` and fires on charts where ``deprecated: true`` is set AND none of the following successor-signal fields are populated:

* ``home:`` (non-empty URL)
* ``sources:`` (non-empty list of URLs)
* annotations matching keys ``deprecation-guide``, ``migration-guide``, ``replacement``, ``successor``, ``replaced-by`` (case-insensitive substring match)

Charts that are deprecated but still maintained (a security-fix-only mode) should populate ``home:`` with the maintenance policy URL so the rule passes.

**Known false-positive modes**

- Internal libraries that go through a 'soft-deprecation' phase before the successor lands sometimes mark ``deprecated: true`` without a successor name in the interim. The rule still fires; suppress per chart with a one-line rationale and a TODO to add the successor annotation when the replacement is ready.

**Seen in the wild**

- Long-running pattern in the Bitnami / community-charts ecosystem: a chart is marked deprecated, the maintainer moves on, consumers continue installing the deprecated version for years without knowing the replacement exists. The successor annotation (or a populated ``home:`` URL) closes the discovery gap.

<div class="pg-rule__rec" markdown>

**Recommended action**

When marking a chart ``deprecated: true``, point consumers at the replacement. The two stable patterns are:

* Set ``sources:`` to the successor repo URL and update ``home:`` to point at the migration guide:

    deprecated: true
    sources:
      - https://github.com/example/myapp-chart-v2
    home: https://example.com/docs/myapp-chart-migration

* Add an explicit migration annotation:

    annotations:
      "helm.sh/migration-guide": "https://example.com/myapp-v2-migration"
      "helm.sh/replacement": "corp-charts/myapp-v2"

A deprecation flag without a successor strands every consumer at the deprecated version. Without active maintenance, security patches don't roll out; consumers either get stuck running known-vulnerable software or have to discover the replacement chart through ad-hoc channels (Slack, GitHub issues, internal wikis) that scale poorly across teams.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## HELM-013: Chart.yaml type field missing or invalid { #helm-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``Chart.yaml`` ``type:`` and fires when the field is missing, empty, or set to a value other than ``application`` / ``library``. The two valid values are defined by the Helm 3 chart schema; other values are ignored by Helm at install time (which is the silent-failure mode the rule catches).

Helm 2 charts (``apiVersion: v1``) are skipped, the ``type:`` field doesn't exist in v1 and HELM-001 already catches the v1 shape.

**Known false-positive modes**

- Some chart-generation tools (early ``helm create`` templates, third-party scaffolders) omit ``type:`` deliberately to defer to Helm's default. The rule still fires; suppress per chart with a rationale, or — better — add the explicit ``type: application`` line.

**Seen in the wild**

- Common refactoring drift: a chart originally written as an ``application`` has its templates pulled out and the ``type:`` forgotten. ``helm install`` against the library-shaped result fails with a cryptic error that doesn't immediately point at the missing type declaration; the chart's review process didn't catch the change because no schema rule was in place.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``type:`` to either ``application`` (the default for deployable charts) or ``library`` (for charts shipped as named templates other charts ``import``). Helm 3 treats missing ``type`` as ``application``, which is permissive but leaves the chart's purpose ambiguous at audit time. An explicit declaration:

* Makes ``helm install`` reject library charts at install time (they have no templates that produce manifests).
* Documents the chart's role for consumers reviewing ``helm search`` output.
* Catches accidental templates added to a library chart during refactor (the install-time rejection surfaces the mistake).

Example:

    apiVersion: v2
    name: myapp
    version: 1.0.0
    type: application   # or 'library' for template-only

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## HELM-014: Chart dependency matches a known-compromised chart registry { #helm-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads the curated registry under ``pipeline_check.core.checks.helm._compromised_charts`` (table of ``(chart_name, malicious_versions, advisory)`` entries) and fires when any ``Chart.yaml`` dependency matches. Registry is hand-curated and append-only; adding an entry is a one-line table edit plus the citing advisory in the commit message.

Mirrors NPM-006 / PYPI-006 / MVN-006 / NUGET-005 / GOMOD-006 / CARGO-006: the rule fires on exact-version equality (with optional regex-fallback patterns shared via ``_primitives/compromised.py``). Coverage is necessarily incomplete; the value is the audit-trail-locked post-incident detection of a published advisory.

**Known false-positive modes**

- Patched fork-and-pin remediation paths sometimes legitimately leave the original chart name pinned at an affected version (with the actual install pointing at a fork). The rule still fires on the Chart.yaml entry; suppress per dependency with a one-line rationale naming the fork and the advisory the patch covers.

**Seen in the wild**

- Future entries follow the same shape as the seeded examples: append ``(chart_name, version, advisory)`` to _compromised_charts.py with the citing advisory in the commit message. Real entries land when public Helm-chart advisories surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump the offending dependency to a patched version named in the cited advisory and run ``helm dependency update`` to refresh ``Chart.lock`` with the new digests. If the advisory has no patched release, pin to the last known-good version and add a follow-up TODO so the dependency is replaced or removed in the next maintenance cycle. After the bump, re-run the scan; HELM-014 should clear. If the rule still fires, an indirect subchart is pulling the bad version back in; inspect ``Chart.lock`` for the dependency path.

</div>

</div>

---

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

If `helm template` exits non-zero (bad template syntax, undefined
values, missing dependency), the chart is recorded in
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

---

## Adding a new Helm check

1. Create a new module at
   `pipeline_check/core/checks/helm/rules/helmNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a
   `check(ctx: HelmContext) -> Finding` function. The orchestrator
   (`HelmChartChecks`) auto-discovers `RULE` and calls `check` with
   the shared `HelmContext` (parsed `Chart` records).
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and
   any other standard that applies).
3. Add unit tests in `tests/helm/rules/test_<name>.py`. Use the
   `make_helm_ctx` fixture to build a synthetic `Chart` record
   without invoking `helm template`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py helm
   ```
