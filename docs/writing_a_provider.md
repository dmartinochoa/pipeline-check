# Writing a provider

How to add a whole new CI/CD platform to the scanner.

A provider binds a platform (GitHub Actions, Cloud Build, an AWS
account, a Dockerfile on disk, …) to a set of check classes that run
against it. Adding one is a focused four-file change — the Scanner
and CLI pick the new provider up automatically once it's registered.

## The minimum surface

Every provider implements three things:

1. **A context object** that holds the parsed input. For
   YAML-on-disk providers this is `<Provider>Context.from_path(path)`
   that walks a directory and builds a list of parsed documents.
   For AWS-shaped providers it holds the boto3 clients and discovered
   resources.
2. **An orchestrator class** subclassing `BaseCheck` that exposes a
   `run() -> list[Finding]`. It auto-discovers per-rule modules from
   `core/checks/<provider>/rules/` (see [Adding a rule](writing_a_rule.md)).
3. **A provider adapter** subclassing `BaseProvider` that wires the
   first two together and registers a `--pipeline <name>` CLI surface.

## Step 1 — Lay out the checks package

```
pipeline_check/core/checks/<provider>/
├── __init__.py
├── base.py          # context dataclass + helpers
├── pipelines.py     # orchestrator (or `manifests.py`, `workflows.py`)
└── rules/
    ├── __init__.py
    └── <prov>001_<slug>.py    # one file per rule
```

`base.py` defines:

- A `<Provider>Context` dataclass / class. Holds the parsed input
  plus `files_scanned`, `files_skipped`, `warnings` for the inventory
  view.
- A `<Provider>BaseCheck(BaseCheck)` class with `PROVIDER =
  "<name>"`. Rules and the orchestrator inherit from it.
- Per-provider helpers (`iter_jobs`, `walk_strings`, …) that the
  rules will share. Keep them small and side-effect-free.

`pipelines.py` (or whatever you name it) is the orchestrator:

```python
from ..rule import discover_rules
from ..base import Finding
from .base import <Provider>BaseCheck

class <Provider>PipelineChecks(<Provider>BaseCheck):
    def __init__(self, ctx, target=None):
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.<provider>.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            for path, doc in self.ctx.documents:    # adapt to your shape
                f = check_fn(path, doc)
                f.cwe = list(rule.cwe)
                findings.append(f)
        return findings
```

The orchestrator is intentionally thin — its only job is to invoke
each rule against each document and collect the results. All the
detection logic lives in the rule modules.

## Step 2 — Add the provider adapter

```python
# pipeline_check/core/providers/<provider>.py
from __future__ import annotations
from typing import Any

from ..checks.base import BaseCheck
from ..checks.<provider>.base import <Provider>Context
from ..checks.<provider>.pipelines import <Provider>PipelineChecks
from ..inventory import Component
from .base import BaseProvider


class <Provider>Provider(BaseProvider):
    NAME = "<name>"

    def build_context(self, <name>_path: str | None = None, **_: Any):
        if not <name>_path:
            raise ValueError(
                "The <name> provider requires --<name>-path "
                "<file-or-dir> pointing at a <name> document."
            )
        return <Provider>Context.from_path(<name>_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [<Provider>PipelineChecks]

    def inventory(self, context) -> list[Component]:
        out: list[Component] = []
        for doc in context.documents:
            out.append(Component(
                provider=self.NAME,
                type="...",
                identifier="...",
                source=doc.path,
                metadata={...},
            ))
        return out
```

`build_context()` accepts `**_` so the Scanner can forward all of
its parameters (region, profile, paths for other providers) without
the new provider needing to declare them.

`inventory()` returns the asset view shown by `pipeline_check
--inventory`. Default is empty; populate it with one `Component`
per document / resource so users can see what was scanned.

## Step 3 — Register in `providers/__init__.py`

```python
from .<provider> import <Provider>Provider

...

register(<Provider>Provider())
```

After this, `pipeline_check --pipeline <name> --<name>-path ...`
works end-to-end.

## Step 4 — Add the CLI flag

`cli.py` declares a `--<name>-path` option for each provider. Add
yours alongside the existing ones, with auto-detection if the
provider has a canonical filename pattern (`Dockerfile`,
`cloudbuild.yaml`, `.gitlab-ci.yml`).

If the provider auto-detects, also extend `_detect_pipeline_from_cwd()`
so `pipeline_check` (no flags) picks it up.

## Step 5 — Fixtures and tests

- `tests/fixtures/workflows/<provider>/insecure-*` and `secure-*`
  documents with positive triggers for every rule.
- `tests/test_workflow_fixtures.py` — add a `Test<Provider>Fixtures`
  class with the `EXPECTED_IDS = {f"<PREFIX>-{i:03d}" for i in
  range(1, N)}` floor.
- `tests/<provider>/conftest.py` — `run_check(snippet, check_id)`
  helper for per-rule unit tests.
- Per-rule modules under `tests/<provider>/test_*.py` with a
  `Test<RULE_ID>` class for each rule.

`tests/test_rule_test_coverage.py` will start enforcing 100%
per-rule test coverage on the new provider once you add it to
`PROVIDERS_AND_FLOORS`.

## Step 6 — Standards mappings

Add the new check IDs to `core/standards/data/owasp_cicd_top_10.py`
and `core/standards/data/nist_800_53.py` at minimum. Other
frameworks (CIS, SLSA, NIST 800-190) are populated as the rules
evidence their controls.

## Step 7 — Provider doc

```bash
python scripts/gen_provider_docs.py <provider>
```

The script reads the rule registry and writes
`docs/providers/<provider>.md`. Add the page to `mkdocs.yml`'s nav
under the Providers section.

## Step 8 — README + index claims

`README.md` and `docs/index.md` carry numerical claims (`16
providers`, `13 standards`). `tests/test_doc_claims.py` derives the
expected values from the registries, so adding a new provider
auto-bumps the expected count — the test fails until the doc
claims match.

The provider table in `README.md` (under `## Supported providers`)
is hand-maintained — add a row for the new provider with its rule
count.

## Inventory and reporters

The reporters (`reporter.py`, `html_reporter.py`, `sarif_reporter.py`,
…) are provider-agnostic. They consume `list[Finding]` plus the
inventory and don't need to change for a new provider.

The HTML reporter does have provider-specific styling for some
inventory views (the pretty asset cards). Most providers don't need
custom CSS — the default table layout works.

## Worked examples

Three different shapes:

- **YAML-on-disk** (CI providers like GitHub, GitLab, CloudBuild) —
  parse a directory of YAML files into a list of documents, run
  each rule against each `(path, doc)`. See
  `core/providers/cloudbuild.py` and
  `core/checks/cloudbuild/base.py` for the canonical small case.
- **API-backed** (AWS) — boto3 clients constructed from
  `--region` / `--profile`, resources discovered via paginators,
  rules call into the cached resource lists. See
  `core/providers/aws.py` and `core/checks/aws/base.py`.
- **Document-centric** (Dockerfile, Kubernetes) — neither YAML
  pipelines nor cloud APIs, but a parser-specific document type.
  See `core/providers/dockerfile.py` for the simplest version.

Pick the closest existing shape and copy from it.
