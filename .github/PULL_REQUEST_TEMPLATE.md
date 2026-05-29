<!--
Thanks for contributing! Keep the PR to one logical change. New to the
rule workflow? `python scripts/new_rule.py <provider> <slug>` scaffolds
the rule module and its test stub. See docs/contributing_first_rule.md.
-->

## What and why

<!-- One or two sentences. The diff shows the "what"; explain the "why". -->

## Type of change

- [ ] New rule or attack chain
- [ ] Bug fix
- [ ] New provider or compliance standard
- [ ] Docs only
- [ ] Refactor / chore / CI

## Checklist

- [ ] Branched from `dev` (not `master`).
- [ ] `python scripts/preflight.py` passes locally (lint, doc-freshness, mypy, tests).
- [ ] Added a `## [Unreleased]` entry to `CHANGELOG.md` under Added / Changed / Fixed.
- [ ] American English throughout (see `CLAUDE.md`).

### If you added or changed a rule

- [ ] Added a `class Test<RULE_ID>...` with both a passing and a failing case.
- [ ] Bumped `EXPECTED_RULE_COUNTS["<provider>"]` in `tests/test_rule_framework.py`.
- [ ] Regenerated the provider doc: `python scripts/gen_provider_docs.py <provider>`.
- [ ] Updated the counts in `README.md` and `docs/index.md` if a registry total changed.
- [ ] (CI providers) extended the `insecure-*` fixture and bumped `EXPECTED_IDS` in `tests/test_workflow_fixtures.py`.
