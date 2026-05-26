# Writing a Rego rule

Pipeline-check can evaluate [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
policies alongside the built-in and YAML custom rule catalogs.
Rego rules are useful when the YAML custom-rule DSL's predicate
operators are too limited: conditional logic, cross-field correlation,
helper functions, and iteration over nested structures are all
natural in Rego.

## Prerequisites

Install the `opa` binary and ensure `opa version` succeeds.
Download from <https://www.openpolicyagent.org/docs/latest/#running-opa>.
Pipeline-check shells out to `opa eval` and `opa inspect` at runtime.

## Quick start

Create a directory for your policies:

```
policies/
  gha_pin.rego
```

Write a policy with `# METADATA` annotations:

```rego
# METADATA
# title: Actions must be pinned to commit SHA
# description: Unpinned actions can be silently replaced by a compromised tag.
# scope: package
# custom:
#   id: ACME-001
#   severity: HIGH
#   provider: github
#   recommendation: Pin every uses reference to a full 40-char commit SHA.
#   cwe: ["CWE-829"]
#   owasp: ["CICD-SEC-3"]
package pipeline_check.github.acme_001

import rego.v1

deny contains result if {
    job := input.doc.jobs[job_name]
    step := job.steps[_]
    uses := step.uses
    not startswith(uses, "./")
    not regex.match(`@[0-9a-f]{40}$`, uses)
    result := {
        "msg": sprintf("Job '%s' uses unpinned action: %s", [job_name, uses]),
        "resource": input.path,
    }
}
```

Run the scan:

```
pipeline_check --pipeline github --rego-rules ./policies/
```

Rego findings flow through scoring, gating, SARIF, and every other
output format exactly like built-in rules.

## Metadata annotations

Each `.rego` file must declare metadata in an OPA `# METADATA` block
at the top of the file, before the `package` declaration.

**Required fields:**

| Field | Description |
|-------|-------------|
| `title` | Short human-readable name. |
| `scope` | Must be `package`. |
| `custom.id` | Stable rule ID matching `[A-Z][A-Z0-9]{1,9}-\d{3}` (e.g. `ACME-001`). Must not collide with a built-in or YAML custom rule. |
| `custom.severity` | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `custom.provider` | The provider this rule targets (e.g. `github`, `gitlab`, `kubernetes`). |

**Optional fields:**

| Field | Description |
|-------|-------------|
| `description` | Longer explanation of what the rule detects. |
| `custom.recommendation` | Remediation guidance shown in reports. |
| `custom.cwe` | CWE identifiers as a list (e.g. `["CWE-829"]`). |
| `custom.owasp` | OWASP CI/CD control references. |
| `custom.esf` | NSA/CISA ESF supply-chain controls. |
| `custom.docs_note` | Extended prose for generated documentation. |

## Input document shape

The Rego policy receives the parsed pipeline document as `input`.
The shape depends on the provider.

### YAML-doc providers (github, gitlab, bitbucket, azure, circleci, cloudbuild)

```json
{
  "path": ".github/workflows/ci.yml",
  "doc": {
    "name": "CI",
    "on": "push",
    "jobs": { ... }
  },
  "provider": "github"
}
```

Access workflow fields via `input.doc.<key>`. The file path is
`input.path`.

### Kubernetes

```json
{
  "manifests": [
    {
      "kind": "Deployment",
      "name": "my-app",
      "namespace": "default",
      "path": "k8s/deploy.yaml",
      "data": { ... }
    }
  ],
  "provider": "kubernetes"
}
```

Iterate manifests via `input.manifests[_]`.

## Deny rule contract

Each policy must define a `deny` rule set. Elements can be:

**String** (simple message):

```rego
deny contains msg if {
    ...
    msg := "Something is wrong"
}
```

**Object** (recommended, carries metadata):

```rego
deny contains result if {
    ...
    result := {
        "msg": "Human-readable description",
        "resource": input.path,
        "severity": "CRITICAL",
    }
}
```

| Key | Required | Description |
|-----|----------|-------------|
| `msg` | Yes | Finding description shown in reports. |
| `resource` | No | File path or resource name. Defaults to `input.path`. |
| `severity` | No | Per-finding severity override. Defaults to the rule's metadata severity. |

When `deny` is empty (no violations), the rule passes.

## Package naming

Use `package pipeline_check.<provider>.<rule_id_snake>`:

```
package pipeline_check.github.acme_001
package pipeline_check.gitlab.sec_002
package pipeline_check.kubernetes.corp_003
```

The package path determines how pipeline-check maps deny-set results
back to rule metadata.

## Supported providers

Rego rules can target any provider. YAML custom rules are limited to
7 providers; Rego has no such restriction because it can handle any
JSON input shape.

| Provider | Input shape |
|----------|------------|
| github, gitlab, bitbucket, azure, circleci, cloudbuild | `{path, doc, provider}` |
| kubernetes, helm | `{manifests, provider}` |
| jenkins, drone, buildkite, tekton, argo, argocd | `{path, doc, provider}` |
| dockerfile, terraform, cloudformation | `{path, doc, provider}` |

## Testing your policies

Use OPA's built-in test runner independently of pipeline-check:

```
opa test ./policies/ -v
```

Or run pipeline-check with `--output json` to inspect findings:

```
pipeline_check --pipeline github --rego-rules ./policies/ --output json
```

## Configuration file

Add Rego rule paths to `.pipeline-check.yml`:

```yaml
rego_rules:
  - ./policies/
  - ./more-policies/
```

Or in `pyproject.toml`:

```toml
[tool.pipeline-check]
rego_rules = ["./policies/"]
```

## Limitations

- Evaluation shells out to the `opa` binary. The `opa` binary must
  be on `PATH`.
- Each `opa eval` invocation has ~50-100ms overhead. For large policy
  sets, group policies in a single directory to minimize invocations.
- `findings_so_far` (access to other rules' results during evaluation)
  is not available in v1.
- Standards-registry mapping is doc-only (via `custom.owasp`,
  `custom.esf`, `custom.cwe` metadata). Rego rules are not
  auto-registered into the authoritative standards data packages.
