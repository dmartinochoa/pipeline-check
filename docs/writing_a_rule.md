# Writing a rule

How to add a new check to an existing provider.

A rule is one Python module under
`pipeline_check/core/checks/<provider>/rules/` that exports two names:

| Name    | Type       | Purpose                                        |
|---------|------------|------------------------------------------------|
| `RULE`  | `Rule`     | Static metadata (id, title, severity, prose)   |
| `check` | callable   | Detection logic that returns a `Finding`       |

The provider's orchestrator walks `rules/` at import time and runs
every `(RULE, check)` pair against the context. No registration call
needed; dropping a file in is enough.

## File naming

Filename pattern: `<id_lower>_<short_slug>.py`.

```
github/rules/gha014_deploy_environment.py
kubernetes/rules/k8s029_default_sa_binding.py
dockerfile/rules/df020_arg_credential_name.py
```

The numeric portion controls discovery order, which controls both the
orchestrator's finding order and the doc generator's section order.
Zero-pad to three digits (`001`, not `1`) so lexical sort matches
numeric sort past `099`.

Modules whose name starts with `_` are skipped, that's how shared
helpers (`_helpers.py`, `_context.py`) coexist with rule modules.

## The minimal rule

```python
"""K8S-029. RoleBinding subjects include the namespace's ``default`` ServiceAccount."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-029",
    title="RoleBinding grants permissions to the default ServiceAccount",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Bind permissions to a dedicated ServiceAccount, not to "
        "``default`` ..."
    ),
    docs_note=(
        "Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists "
        "``kind: ServiceAccount, name: default`` among its subjects ..."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m in ctx.manifests:
        ...
    passed = not offenders
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description="..." if passed else f"{len(offenders)} ...",
        recommendation=RULE.recommendation, passed=passed,
    )
```

Read any existing `rules/<id>_<slug>.py` for the canonical shape, the
codebase has 200+ examples to crib from.

### `Rule` fields

| Field            | Required | Notes                                                 |
|------------------|----------|-------------------------------------------------------|
| `id`             | yes      | `<PROVIDER>-<NNN>`. Globally unique.                  |
| `title`          | yes      | One short sentence; appears in tables and reports.    |
| `severity`       | yes      | `Severity.{CRITICAL,HIGH,MEDIUM,LOW}`.                |
| `owasp`          | no       | OWASP CICD-SEC controls evidenced. Doc-only.          |
| `esf`            | no       | NSA ESF controls. Doc-only.                           |
| `cwe`            | no       | CWE IDs. Surfaces in SARIF.                           |
| `recommendation` | yes      | One paragraph. Shown in every finding + the doc.      |
| `docs_note`      | yes      | Longer prose for the provider doc page.               |
| `known_fp`       | no       | Tuple of false-positive modes shown by `--explain`.   |

`owasp` / `esf` on `Rule` are doc-generation hints. The
*authoritative* mapping for compliance evidence lives in
`core/standards/data/<framework>.py`. See [Standards mappings](#standards-mappings)
below.

### The `check` callable

The signature varies by provider:

| Provider                     | Signature                              |
|------------------------------|----------------------------------------|
| GitHub / GitLab / Bitbucket / Azure / CircleCI / Jenkins / CloudBuild | `check(path: str, doc: dict) -> Finding` |
| Dockerfile                   | `check(df: Dockerfile) -> Finding`     |
| Kubernetes                   | `check(ctx: KubernetesContext) -> Finding` |
| AWS / Terraform / CloudFormation | class-based, see existing modules. |

The function MUST return exactly one `Finding`. For per-offender
findings, accumulate offenders into a list and emit one summary
finding (`f"{n} offender(s): {first_5}..."`). This keeps the report
compact and the per-rule run cost predictable.

## Cross-provider primitives

If the detection is cross-provider (curl-pipe shells, TLS-bypass
flags, container-image classification), prefer to add a primitive
under `core/checks/_primitives/` and have the rule wrap it. The
existing primitives live there and are imported by multiple
providers' rules:

```
_primitives/
├── container_image.py     # AWS / Terraform / CloudFormation CB-009
├── deploy_names.py        # the canonical "deploy" regex
├── lockfile_integrity.py  # GHA-029, GL-027, BB-027, ADO-028, CC-028, JF-031
├── remote_script_exec.py  # GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016
├── secret_shapes.py       # AKIA / *_KEY / *_TOKEN regexes
├── shell_eval.py          # GHA-028, GL-026, BB-026, ADO-027, CC-027, JF-030
└── tls_bypass.py          # GHA-023, GL-023, BB-023, ADO-023, CC-023, JF-023
```

Each primitive returns a structured dataclass (e.g.
`RemoteExecFinding(kind, interpreter, url, host, vendor_trusted)`)
that the per-provider rule wraps in a `Finding`.

## Tests

Add at least one `class Test<RULE_ID>...` with a positive (rule
fails on a known-bad fixture) and a negative (rule passes on a
known-good fixture) test. The provider's `tests/<provider>/`
directory has a `conftest.py` exposing a `run_check(snippet,
check_id)` helper.

```python
from .conftest import run_check


class TestK8S029DefaultSABinding:
    def test_fails_on_rolebinding_to_default_sa(self):
        binding = {"kind": "RoleBinding", ...}
        f = run_check(binding, "K8S-029")
        assert not f.passed

    def test_passes_on_named_serviceaccount(self):
        binding = {"kind": "RoleBinding", ...}
        f = run_check(binding, "K8S-029")
        assert f.passed
```

`tests/test_rule_test_coverage.py` enforces 100% per-rule test
coverage on every CI provider, if you ship a rule without a
`Test<RULE_ID>` class, that meta-test fails.

## Fixtures

Each provider has an `insecure-*` and `secure-*` omnibus fixture
under `tests/fixtures/workflows/<provider>/`. Add a positive trigger
for your new rule to the insecure fixture and verify the secure
fixture still passes. Bump the `EXPECTED_IDS = {f"{prefix}-{i:03d}"
for i in range(1, N)}` upper bound in `tests/test_workflow_fixtures.py`.

## Standards mappings

Map the new check ID to controls in any of the standards files
under `core/standards/data/<framework>.py`:

```python
mappings={
    ...
    "K8S-029":  ["CICD-SEC-2", "CICD-SEC-5"],
    ...
}
```

`tests/test_standards.py` enforces that every mapped control is
defined in the standard's `controls={...}` table, drop a control
that isn't listed there and the test fails. NIST 800-53 and OWASP
CICD Top 10 are the two that most rules end up in.

## Doc generation

The provider reference doc is regenerated from the rule registry:

```bash
python scripts/gen_provider_docs.py kubernetes
# or for every provider:
python scripts/gen_provider_docs.py
```

`tests/test_rule_framework.py` fails until the regenerated doc is
committed. Hand edits to `docs/providers/<provider>.md` get
overwritten on the next regeneration, change the rule's
`recommendation` / `title` / `docs_note` instead and re-run the
generator.

## Confidence demotion

Heuristic rules whose match shape is known to misfire on legitimate
patterns can be added to the demotion list in
`core/checks/_confidence.py`. The scanner will then drop the
confidence to LOW unless the finding sets
`confidence_locked = True`.

## Autofix

Most rules don't need an autofix. If the fix is a single-line patch
(comment-out an unsafe line, drop a flag, flip a boolean), register
a fixer in the `core/autofix/` package (the `_FIXERS` registry is
the entry point; implementation modules sit alongside it). Look at
the existing fixers for the pattern. Comment-only TODOs are
preferred for ambiguous cases.

## What NOT to do

- **Don't** edit `docs/providers/<provider>.md` directly. It's
  generated.
- **Don't** add the rule's metadata to multiple places (the registry
  was the whole point of the `Rule` framework).
- **Don't** import from `core.checks.<other_provider>`: primitives
  go in `_primitives/`, not in another provider's namespace.
- **Don't** introduce a per-rule fixture YAML if you can extend the
  shared `insecure-*` / `secure-*` files instead. Per-rule fixtures
  are reserved for cases the omnibus fixture genuinely can't
  represent (mutually-exclusive triggers, multi-document scenarios).
