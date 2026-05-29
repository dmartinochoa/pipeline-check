# Contributing to Pipeline-Check

Thanks for considering a contribution. This is a solo-maintained
open-source project, so the process is light, but a few conventions
keep the codebase coherent.

## Quick orientation

- Source lives under `pipeline_check/`. Tests live under `tests/`.
- Per-provider rules live in
  `pipeline_check/core/checks/<provider>/rules/<id>_<name>.py`.
- Compliance-standard mappings live in
  `pipeline_check/core/standards/data/<name>.py`.
- Provider and standard documentation pages under `docs/providers/`
  and `docs/standards/` are generated from the registries. See the
  "Generated docs" section below.
- Project-wide conventions live in [CLAUDE.md](CLAUDE.md). Read it.

## Development setup

Python 3.11 or newer is required. From a fresh clone:

```bash
make install       # installs pinned dev deps via --require-hashes, then -e .
```

Or, if you prefer an ad-hoc install without the lockfile:

```bash
pip install -e ".[dev]"
```

The `dev` extra pulls in `pytest`, `pytest-cov`, `mypy`, `ruff`,
`jsonschema`, and `types-PyYAML` at the floor versions declared in
`pyproject.toml`.

Install the project's internal pre-commit hooks so the four
drift-test suites (docs <-> code) gate every push:

```bash
pip install pre-commit
pre-commit install                       # ruff lint on every commit
pre-commit install --hook-type pre-push  # drift tests on every push
```

Config lives at `.pre-commit-config.yaml`. Skip with
`git commit --no-verify` / `git push --no-verify` only when you
have a reason (and a follow-up commit).

## Tests, lint, types

The one-command pre-PR gate is:

```bash
python scripts/preflight.py        # or: make check
```

It runs lint, doc-freshness, strict mypy, and the test suite the same
way CI does, then prints a pass/fail summary. Add `--quick` to swap the
full suite for the fast drift/framework subset while iterating.

The individual commands, to run one at a time:

```bash
make test          # pytest with coverage
make lint          # ruff check pipeline_check tests scripts
python -m mypy pipeline_check
```

CI runs the same commands plus a few integration jobs (LocalStack,
GOAT benchmark, dogfood). The full test suite takes about 2 minutes
locally.

Strict mypy is on. All nine `mypy --strict` flags are enabled, with
a handful of documented per-module carve-outs in `pyproject.toml`
for boto3 wrappers and PyYAML subclasses.

## Generated documentation

Two doc trees are generated from registries and will fail CI if you
hand-edit them and forget to regenerate:

```bash
python scripts/gen_provider_docs.py            # all providers
python scripts/gen_provider_docs.py kubernetes # one provider

python scripts/gen_standards_docs.py                   # all standards
python scripts/gen_standards_docs.py owasp_cicd_top_10 # one standard
```

To change a rule's title, recommendation, or `docs_note`, edit the
rule module under `pipeline_check/core/checks/<provider>/rules/`
and regenerate. `tests/test_rule_framework.py` will fail until the
regenerated pages are committed.

## Numerical claims in docs

Counts in README and `docs/index.md` ("32 providers", "18 standards",
"111 autofixers", "50 attack chains", "1060+ checks") are pinned to
the live registries by `tests/test_doc_claims.py`. Adding a new
provider or rule will bump the expected count automatically. If
the test fails, update the README and `docs/index.md` to match.

## English variant

This project uses American English everywhere (source, docs, CLI
output, commit messages). `tests/test_english_variant.py` fails the
suite on drift. The exhaustive avoid/use list lives in
[CLAUDE.md](CLAUDE.md). After a large import, you can run
`scripts/_apply_american_english.py` to convert in one pass.

## Test fixtures and Scorecard

Files under `tests/fixtures/` and `bench/cases/` are intentionally
insecure: they exist as negative test cases for the project's own
rules. OpenSSF Scorecard's `PinnedDependenciesID` check flags these
as security findings.

The Scorecard workflow (`.github/workflows/scorecard.yml`) strips
any SARIF result whose `artifactLocation.uri` starts with `tests/`
or `bench/` before uploading to code scanning. If you add a new
vulnerable-by-design fixture under either tree, the filter covers
it automatically. No manual exemption is needed.

## Adding a new rule

The fast path is the scaffold tool, which does steps 1-3 below for you:

```bash
python scripts/new_rule.py github self_hosted_runner --apply
```

It picks the next free ID, writes the rule module and a matching test
stub, and prints the remaining checklist. The full walkthrough is
[Your first rule in 10 minutes](docs/contributing_first_rule.md). The
manual steps, for reference:

1. Pick the next free ID for the provider (`grep` the rules
   directory for the highest in-use ID).
2. Create `pipeline_check/core/checks/<provider>/rules/<id>_<name>.py`
   following the same shape as nearby rules.
3. Add a unit test under `tests/<provider>/` that exercises
   both a pass and a fail fixture.
4. If the rule provides evidence for a compliance control, wire it
   up in `pipeline_check/core/standards/data/<name>.py`.
5. Regenerate the provider and (if applicable) standards docs.
6. Run the full test suite.

`tests/test_rule_framework.py` enforces the shape of rule modules
and will tell you what's missing.

## Pull-request workflow

- Branch from `dev`, not `master`. Releases are cut from `dev` to
  `master`.
- One logical change per PR. Bundled refactors are fine when the
  intent is one thing (the project history has examples).
- Append your entry to the `## [Unreleased]` section at the top of
  `CHANGELOG.md`, under `### Added`, `### Changed`, or `### Fixed`.
  Drop empty subheadings. The release commit promotes
  `[Unreleased]` to a dated version; you don't need to bump
  `pyproject.toml` yourself.
- CI must be green before merge.

## Commit style

Conventional-style prefixes (`feat:`, `fix:`, `docs:`, `chore:`,
`refactor:`, `test:`, `ci:`) with an optional scope. Recent
examples from `git log`:

```
fix(history): tolerate mtime stat race + wrap CLI write OSError
fix(k8s): canonicalize default namespace in K8S-013 ServiceAccount anchor
docs(changelog): consolidate the two AC-005 entries to one timeline
```

Subject line under 72 characters. Body wraps at 72 too. Explain
the why; the what is in the diff.

## Reporting issues

- Bugs and feature requests: use the
  [issue templates](.github/ISSUE_TEMPLATE/).
- False positives: there's a dedicated template. Include the rule
  ID, the offending fixture (redacted), and the scanner version.
- Security issues: **do not** open a public issue. Follow
  [SECURITY.md](SECURITY.md) and use GitHub's private vulnerability
  reporting.

## Releases

Maintainer-only. The process is documented in [CLAUDE.md](CLAUDE.md)
under "Release process".
