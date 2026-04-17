"""Unit tests for the new CC rules (CC-029 machine image, CC-030 context gate).

Complements the fixture-based tests in test_workflow_fixtures.py with
edge-case coverage that the single insecure/secure fixture pair can't
express.
"""
from __future__ import annotations

import pytest
import yaml

from pipeline_check.core.checks.circleci.rules import (
    cc029_machine_image,
    cc030_context_ungated,
)


def _doc(text: str) -> dict:
    return yaml.safe_load(text)


# ──────────────────────────────────────────────────────────────────────
# CC-029 — machine executor image not pinned
# ──────────────────────────────────────────────────────────────────────

class TestCC029:
    @pytest.mark.parametrize("image", [
        "ubuntu-2204:current",
        "ubuntu-2204:edge",
        "ubuntu-2204:default",
        "ubuntu-2204",            # no tag at all
        "android:2024",           # partial version — fails the dated-tag regex
    ])
    def test_rolling_or_bare_tag_fails(self, image):
        doc = _doc(f"""
version: 2.1
jobs:
  x:
    machine:
      image: {image}
    steps: [checkout]
""")
        f = cc029_machine_image.check("<test>", doc)
        assert f.passed is False

    def test_machine_true_fails(self):
        # ``machine: true`` uses CircleCI's default image — rolling.
        doc = _doc("""
version: 2.1
jobs:
  x:
    machine: true
    steps: [checkout]
""")
        f = cc029_machine_image.check("<test>", doc)
        assert f.passed is False

    @pytest.mark.parametrize("image", [
        "ubuntu-2204:2024.05.1",
        "ubuntu-2204:2024.1",          # 2-part dated tag
        "android:2024.01.1-node.20",   # dated tag plus suffix
    ])
    def test_dated_tag_passes(self, image):
        doc = _doc(f"""
version: 2.1
jobs:
  x:
    machine:
      image: {image}
    steps: [checkout]
""")
        f = cc029_machine_image.check("<test>", doc)
        assert f.passed is True

    def test_no_machine_executor_silent_pass(self):
        doc = _doc("""
version: 2.1
jobs:
  x:
    docker:
      - image: cimg/node:20@sha256:aaa
    steps: [checkout]
""")
        f = cc029_machine_image.check("<test>", doc)
        assert f.passed is True
        assert "No machine executor" in f.description


# ──────────────────────────────────────────────────────────────────────
# CC-030 — context without branch filter or approval gate
# ──────────────────────────────────────────────────────────────────────

class TestCC030:
    def test_context_no_gate_fails(self):
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - deploy:
          context: prod-secrets
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is False
        assert "w/deploy" in f.description

    def test_context_with_branch_filter_passes(self):
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - deploy:
          context: prod-secrets
          filters:
            branches:
              only: main
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is True

    def test_context_with_approval_predecessor_passes(self):
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - hold:
          type: approval
      - deploy:
          context: prod-secrets
          requires: [hold]
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is True

    def test_context_list_form_also_gated(self):
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - deploy:
          context:
            - prod-secrets
            - npm-publish
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is False

    def test_approval_jobs_themselves_skipped(self):
        # An approval job doesn't execute a shell — even though it may
        # reference a context, it's not loading secrets into a runner.
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - gate:
          type: approval
          context: ignored
      - deploy:
          context: prod-secrets
          requires: [gate]
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is True

    def test_approval_scoped_per_workflow(self):
        # An approval in workflow A does not gate deploys in workflow B.
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  a:
    jobs:
      - hold:
          type: approval
  b:
    jobs:
      - deploy:
          context: prod-secrets
          requires: [hold]
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is False

    def test_no_context_silent_pass(self):
        doc = _doc("""
version: 2.1
jobs:
  deploy: {docker: [{image: "x:1"}], steps: [checkout]}
workflows:
  w:
    jobs:
      - deploy
""")
        f = cc030_context_ungated.check("<test>", doc)
        assert f.passed is True
