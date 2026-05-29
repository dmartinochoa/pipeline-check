# Your first rule in 10 minutes

This is the fast path: scaffold a rule, fill in the detection, run one
gate, open the PR. For the full reference (every `Rule` field, the
per-provider `check` signatures, cross-provider primitives, autofix,
standards mappings) see [Adding a rule](writing_a_rule.md).

We will add a GitHub Actions rule as the worked example. GitHub has the
most rules and the simplest `check` signature, so it is the easiest
place to start.

## 0. Set up (once)

```bash
pip install -e ".[dev]"          # or: make install (hash-locked deps)
pre-commit install               # ruff on commit
pre-commit install --hook-type pre-push   # drift tests on push
```

## 1. Scaffold the rule

```bash
python scripts/new_rule.py github schedule_without_permissions --severity MEDIUM --apply
```

This picks the next free ID, writes the rule module and a matching test
stub, and prints the remaining checklist:

```
created pipeline_check/core/checks/github/rules/gha107_schedule_without_permissions.py
created tests/github/test_schedule_without_permissions.py
```

(Drop `--apply` to preview the files without writing them.) The module
is born with a passing stub `check`, so it is already discoverable and
the suite still imports. Your job is to replace the stub with real
logic.

## 2. Write the detection

Open the new module. The scaffold gives you the imports, a `RULE` block
with `TODO` prose, and a stub `check`. Replace the `TODO` prose, then
write the body. For this example we flag a workflow that runs on a
`schedule:` trigger but sets no top-level `permissions:` (so it inherits
the broad default token).

```python
"""GHA-107. Scheduled workflow without an explicit permissions block."""

from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import workflow_triggers   # add the helper you need

RULE = Rule(
    id="GHA-107",
    title="Scheduled workflow runs with the default token scope",
    severity=Severity.MEDIUM,
    recommendation=(
        "Set a top-level `permissions:` block (start from "
        "`permissions: { contents: read }`) so the scheduled run does "
        "not inherit the broad default GITHUB_TOKEN scope."
    ),
    docs_note=(
        "Fires when a workflow's `on:` includes `schedule` and the "
        "workflow has no top-level `permissions:` key."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    scheduled = "schedule" in workflow_triggers(doc)
    has_permissions = "permissions" in doc
    passed = not (scheduled and not has_permissions)
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=(
            "Scheduled workflow has no top-level permissions block."
            if not passed
            else "No issue detected."
        ),
        recommendation=RULE.recommendation,
        passed=passed,
    )
```

Read a neighboring rule (`gha105_self_hosted_untrusted_trigger.py` is a
good one) for the helpers available on `..base` and the house style for
the prose fields.

## 3. Write the tests

Open `tests/github/test_schedule_without_permissions.py`. The scaffold
left a passing `test_metadata` and two skipped behavioral stubs. Replace
the skips with real cases using the provider's `run_check` helper:

```python
from .conftest import run_check

CHECK_ID = "GHA-107"


class TestGHA107:
    def test_fails_on_schedule_without_permissions(self):
        wf = """
        on: { schedule: [{ cron: "0 0 * * *" }] }
        jobs: { b: { runs-on: ubuntu-latest, steps: [{ run: echo hi }] } }
        """
        assert not run_check(wf, CHECK_ID).passed

    def test_passes_with_permissions(self):
        wf = """
        on: { schedule: [{ cron: "0 0 * * *" }] }
        permissions: { contents: read }
        jobs: { b: { runs-on: ubuntu-latest, steps: [{ run: echo hi }] } }
        """
        assert run_check(wf, CHECK_ID).passed
```

`tests/test_rule_test_coverage.py` requires a `class Test<RULE_ID>` for
every CI-provider rule, so keep the class name in sync with the ID.

## 4. Bump the drift gates

The scaffold printed these. The framework makes the count bump a
deliberate step, so it is not automated:

1. Set `EXPECTED_RULE_COUNTS["github"] = 98` in
   `tests/test_rule_framework.py`.
2. Add a positive trigger to `tests/fixtures/workflows/github/insecure-*`
   and bump `EXPECTED_IDS` in `tests/test_workflow_fixtures.py`.
3. Regenerate the provider doc:
   `python scripts/gen_provider_docs.py github`.
4. Update the check count in `README.md` and `docs/index.md`
   (`tests/test_doc_claims.py` pins them).

## 5. Run the gate

```bash
python scripts/preflight.py --quick   # lint, doc-freshness, mypy, drift tests
python scripts/preflight.py           # the full suite before you push
```

`preflight.py` runs the same checks CI does, so a green run locally means
a green run on the PR.

## 6. Open the PR

- Branch from `dev`, not `master`.
- Add a `## [Unreleased]` entry to `CHANGELOG.md` under `### Added`.
- Fill in the PR template checklist.

That is the whole loop. Map the rule to a compliance control or add an
autofix when it fits; both are optional and covered in
[Adding a rule](writing_a_rule.md).

## Going deeper

- [Adding a rule](writing_a_rule.md): the complete reference.
- [Adding an attack chain](writing_a_chain.md): correlate findings into
  a kill chain.
- [Adding a provider](writing_a_provider.md): wire up a brand-new
  ecosystem.
