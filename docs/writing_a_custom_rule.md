# Writing a custom rule

Pipeline-Check ships with a 1100+ rule built-in catalog, but every
org has policies the catalog can't anticipate: an internal-only
container registry, a banned dependency, a forbidden runner label.
Custom rules fill that gap. Drop a YAML file under `--custom-rules
PATH`, and your rule appears in findings, scoring, gating, SARIF,
and `--explain` exactly like a built-in.

For rules that need conditional logic, cross-field correlation, or
helper functions beyond the YAML DSL, see
[Writing a Rego rule](writing_a_rego_rule.md).

## Where rules live

Three ways to load custom rules, in priority order:

1. **CLI**: `pipeline_check --custom-rules ./security/rules.yml ...`
   (repeatable for multiple paths).
2. **Config file**: `custom_rules:` key in `.pipeline-check.yml` or
   `pyproject.toml`.
3. **Convention**: drop `*.yml` files under any directory you pass
   to `--custom-rules`. The loader walks recursively.

A path may be a single file or a directory of files. Directories are
walked for `*.yml` / `*.yaml`.

## A first rule

```yaml
# security/no-internal-images.yml
rules:
  - id: ACME-001
    title: Container image must come from acme.io registry
    severity: HIGH
    provider: kubernetes
    description: |
      Container {{name}} pulls from {{image}}, which is not the
      acme.io registry.
    recommendation: |
      Use acme.io/<team>/<image>:<tag> or build the image internally.
      External registries are not allowed for production workloads.

    for_each: $.workloads[*].containers[*]
    assert:
      regex:
        path: image
        pattern: "^acme\\.io/"
```

That's a complete rule. Save it, run:

```bash
pipeline_check --pipeline kubernetes --k8s-path k8s/ \
    --custom-rules ./security/no-internal-images.yml
```

Every container that doesn't pull from `acme.io/` becomes an
offender in the rule's finding.

## Rule shape

Every rule must define:

| Field | Purpose |
|-------|---------|
| `id` | Stable check ID. Format: `^[A-Z][A-Z0-9]{1,9}-\d{3}$`, e.g. `ACME-001`, `ORG7-014`. Must not collide with a built-in (`GHA-*`, `K8S-*`, `GCB-*`, …), the loader rejects collisions at load time. |
| `title` | One-line summary shown in reports. |
| `severity` | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `provider` | One of `github`, `gitlab`, `bitbucket`, `azure`, `circleci`, `cloudbuild`, `kubernetes`. AWS / Terraform / CloudFormation / Dockerfile aren't supported in 1.x. Helm rules use `provider: kubernetes` because the Helm provider reuses the K8s rule pack on rendered manifests. |
| `description` | Per-offender description template. `{{ name }}` placeholders interpolate fields from the iterated node first, falling back to ambient context. |
| `recommendation` | What to do to fix the violation. Shown in reports and `--explain`. |
| `for_each` | A jsonpath into the doc selecting nodes to evaluate. Each match is one potential offender. |
| `assert` | A predicate. Nodes where `assert` evaluates to **true** pass; nodes where it evaluates to **false** become offenders. |

Optional:

| Field | Purpose |
|-------|---------|
| `docs_note` | Multi-paragraph extended explanation surfaced by `--explain`. |
| `cwe` | List of CWE identifiers (e.g. `["CWE-829"]`). |
| `owasp` | List of OWASP CICD-SEC controls. Doc-only; no automatic standards-registry mapping for custom rules in 1.x. |
| `esf` | List of NSA/CISA ESF controls. Same caveat. |

## jsonpath subset

Custom rules walk the parsed pipeline document with a small jsonpath
subset:

```
$               root document
.field          literal field access (alphanumeric + underscore only)
['key']         quoted field access (use for keys with dashes/dots)
[N]             list index (negative indices allowed)
[*]             list / dict wildcard
.*              shorthand for [*]
```

Anything else (recursive descent `..`, filters `?`, slicing `[a:b]`,
unions `,`) is intentionally out, when you need them, write the
rule in Python.

Inside `assert.<op>.path`, the path is rooted at the iterated node
(the result of one `for_each` match). A bare name is sugar:
`path: image` is `path: $.image`.

## Predicate operators

Every predicate is a YAML mapping with exactly one operator key.
Operators come in three flavors: leaf, comparison, and boolean.

### Leaf

| Operator | Args | Meaning |
|----------|------|---------|
| `eq` | `path`, `value` | first match equals `value` |
| `ne` | `path`, `value` | first match != `value` (missing field is "not equal") |
| `regex` | `path`, `pattern` | first string match matches `pattern` |
| `not_regex` | `path`, `pattern` | first string match does NOT match `pattern` |
| `in` | `path`, `values` | first match is in `values` list |
| `not_in` | `path`, `values` | first match is NOT in `values` (missing field is "not in") |
| `exists` | `path` | path resolves to ≥1 match |
| `missing` | `path` | path resolves to 0 matches |

### Numeric comparison

`gt` / `lt` / `gte` / `lte`. Each takes `path` and a numeric `value`.
Non-numeric values evaluate to false.

### Length

`len_eq` / `len_gt` / `len_lt`. Each takes `path` (resolving to a
list, string, or dict) and an integer `value`.

### Boolean glue

```yaml
assert:
  not:
    any_of:
      - eq:    { path: securityContext.privileged, value: true }
      - regex: { path: image, pattern: ":latest$" }
      - missing: { path: resources.limits.memory }
```

Empty `all_of: []` and `any_of: []` are rejected at load time. `not`
takes a single child predicate.

## Description template

The description is a string with `{{ ... }}` placeholders. Two
forms:

- **`{{ name }}`**: bare name. Resolves first against the iterated
  node's `$.name`, then against ambient context (provider-specific:
  `kind`, `namespace`, etc. for Kubernetes; `path`, `job`, `step` for
  GHA). Missing → `?`.
- **`{{ $.foo.bar }}`**: explicit jsonpath. Always resolves against
  the iterated node, no ambient fallback.

Render errors fall back to a literal `?` rather than aborting the
scan.

## Per-provider doc shape

The doc your rule walks is the parsed YAML / synthesized view for
that provider. Key roots:

### GitHub Actions (`provider: github`)

The parsed workflow document, rooted at the workflow object:

```
$.name
$.on                           # parsed event spec
$.permissions
$.jobs.<name>                  # one entry per job key
$.jobs.<name>.runs-on
$.jobs.<name>.steps[*]
$.jobs.<name>.steps[*].uses
$.jobs.<name>.steps[*].run
$.jobs.<name>.steps[*].with    # action inputs
```

Ambient: `path` (workflow file path).

### GitLab CI / Bitbucket / Azure DevOps / CircleCI / Cloud Build

The parsed pipeline file rooted at `$`. Each provider has its own
canonical shape, see the upstream YAML schema documentation for
field names.

### Kubernetes / Helm (`provider: kubernetes`)

A synthesized per-manifest view that flattens the kind-specific
pod-spec paths into a uniform shape:

```
$.kind                         # e.g. "Deployment"
$.name
$.namespace
$.api_version
$.metadata                     # raw metadata dict
$.spec                         # raw spec dict
$.raw                          # entire parsed manifest, escape hatch
$.workloads[*]                 # 0 or 1 entries (per pod-spec resource)
$.workloads[*].containers[*]   # init + main + ephemeral, normalized
$.workloads[*].containers[*].name
$.workloads[*].containers[*].image
$.workloads[*].containers[*].securityContext
$.workloads[*].containers[*].container_kind   # "container" | "initContainer" | "ephemeralContainer"
$.workloads[*].volumes[*]
$.workloads[*].service_account
$.workloads[*].host_network    # bool
$.workloads[*].host_pid        # bool
$.workloads[*].host_ipc        # bool
$.workloads[*].spec            # raw pod spec
```

Ambient: `kind`, `name`, `namespace`, `path`.

The container's classifier is exposed as `container_kind` rather
than `kind` so it doesn't shadow the manifest's kind in description
templates. A custom rule writing `{{ kind }}` from inside a
container loop gets the manifest kind via ambient fallback.

Helm rules use `provider: kubernetes`. The Helm provider renders
charts via `helm template` and runs the K8s rule pack (built-in +
custom) on the result, so a rule written for Kubernetes
automatically applies to Helm-deployed workloads.

## ID validation and collisions

- `id` must match `^[A-Z][A-Z0-9]{1,9}-\d{3}$`. The first 2–10 chars
  are a prefix of your choosing (org / team / project) and the
  trailing 3 digits are a sequence.
- The loader rejects IDs that match any built-in check ID. Pick a
  prefix that's clearly yours, `ACME`, `ORG`, `MYCO7`, to keep
  custom rules unambiguous in reports.
- Duplicate IDs across rule files are also rejected.

## What's not in the custom-rule DSL today

- **Inline tests.** A `tests:` block on the rule is on the roadmap;
  for now, write a quick fixture and run the rule through the
  Scanner manually to verify.
- **Standards mapping.** Custom rules can declare `owasp:` / `esf:` /
  `cwe:` lists, but those are doc-only, the standards registry
  doesn't pick them up automatically. Custom findings appear in
  reports without compliance-control attribution.
- **Custom autofix.** A custom rule can flag, not patch.
- **Cross-provider rules.** Each rule pins to one provider.
- **AWS / Terraform / CloudFormation / Dockerfile providers.** Their
  resource graph / instruction stream doesn't fit the dict-tree DSL.

## Examples

### Forbid floating GHA action references

```yaml
rules:
  - id: ACME-001
    title: Action must be pinned to a 40-char SHA
    severity: HIGH
    provider: github
    description: 'step uses {{uses}} not pinned to a 40-char commit SHA'
    recommendation: Pin to a 40-char SHA. Use Dependabot or StepSecurity.
    for_each: $.jobs.*.steps[*]
    assert:
      regex:
        path: uses
        pattern: '^[^@]+@[0-9a-f]{40}$'
```

### Block a banned dependency in CircleCI

```yaml
rules:
  - id: ACME-010
    title: Banned orb 'sketchy/example'
    severity: CRITICAL
    provider: circleci
    description: 'job {{name}} pulls in banned orb sketchy/example'
    recommendation: Replace with the internal orb 'acme/build-tools'.
    for_each: $.orbs.*
    assert:
      not:
        regex:
          path: $
          pattern: '^sketchy/example@'
```

### Require a memory limit on every Kubernetes container

```yaml
rules:
  - id: ACME-101
    title: Container missing resources.limits.memory
    severity: MEDIUM
    provider: kubernetes
    description: 'container {{name}} in {{kind}}/{{name}} has no memory limit'
    recommendation: Set resources.limits.memory on every container.
    for_each: $.workloads[*].containers[*]
    assert:
      exists:
        path: resources.limits.memory
```

### Forbid `latest` tags AND missing memory limits at the same time

```yaml
rules:
  - id: ACME-102
    title: Container fails the production posture gate
    severity: HIGH
    provider: kubernetes
    description: 'container {{name}} fails one or more gates'
    recommendation: |
      Use a digest-pinned image and set resources.limits.memory.
    for_each: $.workloads[*].containers[*]
    assert:
      all_of:
        - not_regex: { path: image, pattern: ':latest$' }
        - exists:    { path: resources.limits.memory }
```

## Performance limits

A rule with a wide `for_each` (e.g. `$.workloads[*].containers[*]`)
runs once per matched node, per scanned manifest. Rules that touch
every node in every doc on a 5000-line repo are noticeable; rules
that walk one container or one step typically aren't.

There's no hard cap on rule cost today. If you're seeing scan
slowdowns after adding custom rules, narrow the `for_each` path so
the predicate runs fewer times.
