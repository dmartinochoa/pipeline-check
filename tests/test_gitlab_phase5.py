"""Unit tests for the new GL rules (GL-028, GL-029, GL-030).

Complements the fixture-based tests in test_workflow_fixtures.py
with edge-case coverage the single insecure/secure pair can't express.
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.gitlab.rules import (
    gl028_services_pinning,
    gl029_manual_allow_failure,
    gl030_trigger_include_pinning,
)


def _doc(text: str) -> dict:
    return yaml.safe_load(text)


# ──────────────────────────────────────────────────────────────────────
# GL-028 — services image pinning
# ──────────────────────────────────────────────────────────────────────

class TestGL028:
    def test_top_level_latest_fails(self):
        doc = _doc("""
services: [postgres:latest]
image: python:3.12.1
build: {script: [make]}
""")
        f = gl028_services_pinning.check("<t>", doc)
        assert f.passed is False
        assert "postgres:latest" in f.description

    def test_top_level_dict_form_bare_fails(self):
        doc = _doc("""
services:
  - name: redis
    alias: cache
image: python:3.12.1
build: {script: [make]}
""")
        f = gl028_services_pinning.check("<t>", doc)
        assert f.passed is False

    def test_per_job_services_digest_passes(self):
        doc = _doc("""
image: python:3.12.1
build:
  services:
    - name: postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      alias: db
  script: [make]
""")
        f = gl028_services_pinning.check("<t>", doc)
        assert f.passed is True

    def test_version_tag_passes(self):
        doc = _doc("""
services: ['postgres:16.2-alpine']
build: {script: [make]}
""")
        f = gl028_services_pinning.check("<t>", doc)
        assert f.passed is True

    def test_no_services_silent_pass(self):
        doc = _doc("""
image: python:3.12.1
build: {script: [make]}
""")
        f = gl028_services_pinning.check("<t>", doc)
        assert f.passed is True
        assert "no ``services:`` entries" in f.description


# ──────────────────────────────────────────────────────────────────────
# GL-029 — manual deploy job lacks allow_failure:false
# ──────────────────────────────────────────────────────────────────────

class TestGL029:
    def test_manual_deploy_without_allow_failure_fails(self):
        doc = _doc("""
deploy-prod:
  when: manual
  script: [./deploy.sh]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is False
        assert "deploy-prod" in f.description

    def test_manual_deploy_with_explicit_false_passes(self):
        doc = _doc("""
deploy-prod:
  when: manual
  allow_failure: false
  script: [./deploy.sh]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is True

    def test_manual_deploy_with_true_fails(self):
        doc = _doc("""
deploy-prod:
  when: manual
  allow_failure: true
  script: [./deploy.sh]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is False

    def test_non_manual_deploy_not_flagged_here(self):
        # GL-004 is the right rule to fail on this shape. GL-029 fires
        # only on manual jobs — non-manual deploys pass trivially.
        doc = _doc("""
deploy-prod:
  script: [./deploy.sh]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is True

    def test_manual_non_deploy_passes(self):
        # A manual test job is fine — allow_failure default doesn't
        # bypass a gate that was never meant as a gate.
        doc = _doc("""
manual-smoketest:
  when: manual
  script: [npm test]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is True

    def test_rules_with_manual_and_no_allow_failure_fails(self):
        doc = _doc("""
deploy-prod:
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: manual
  script: [./deploy.sh]
""")
        f = gl029_manual_allow_failure.check("<t>", doc)
        assert f.passed is False


# ──────────────────────────────────────────────────────────────────────
# GL-030 — trigger:include: source pinning
# ──────────────────────────────────────────────────────────────────────

class TestGL030:
    def test_branch_ref_fails(self):
        doc = _doc("""
trig:
  trigger:
    include:
      - project: 'team/pipelines'
        ref: main
""")
        f = gl030_trigger_include_pinning.check("<t>", doc)
        assert f.passed is False
        assert "team/pipelines" in f.description

    def test_tag_ref_passes(self):
        doc = _doc("""
trig:
  trigger:
    include:
      - project: 'team/pipelines'
        ref: v1.2.3
""")
        f = gl030_trigger_include_pinning.check("<t>", doc)
        assert f.passed is True

    def test_missing_ref_fails(self):
        doc = _doc("""
trig:
  trigger:
    include:
      - project: 'team/pipelines'
""")
        f = gl030_trigger_include_pinning.check("<t>", doc)
        assert f.passed is False

    def test_remote_url_fails(self):
        doc = _doc("""
trig:
  trigger:
    include:
      - remote: 'https://gitlab.example.com/snippets/42/raw'
""")
        f = gl030_trigger_include_pinning.check("<t>", doc)
        assert f.passed is False
        assert "remote" in f.description

    def test_no_trigger_include_silent_pass(self):
        doc = _doc("""
build:
  script: [make]
""")
        f = gl030_trigger_include_pinning.check("<t>", doc)
        assert f.passed is True
