"""Unit tests for GCB-023..026 (round 15 expansion)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb023_undeclared_user_substitution as r23,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb024_images_missing as r24,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb025_tags_empty as r25,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb026_waitfor_dangling as r26,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


# ──────────────────────────────────────────────────────────────────
# GCB-023 — undeclared user substitution
# ──────────────────────────────────────────────────────────────────


class TestGCB023UndeclaredUserSub:
    def test_fails_when_step_uses_undeclared_sub(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["push", "gcr.io/$PROJECT_ID/myapp:$_REGON"],
        }], substitutions={"_REGION": "us-central1"})
        f = r23.check("cb.yaml", doc)
        assert not f.passed
        assert "_REGON" in f.description

    def test_passes_when_sub_is_declared(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["push", "gcr.io/$PROJECT_ID/myapp:$_REGION"],
        }], substitutions={"_REGION": "us-central1"})
        assert r23.check("cb.yaml", doc).passed

    def test_passes_with_braced_form(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["push", "${_REGION}"],
        }], substitutions={"_REGION": "us-central1"})
        assert r23.check("cb.yaml", doc).passed

    def test_fails_with_braced_undeclared_form(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["push", "${_REGON}"],
        }], substitutions={"_REGION": "us-central1"})
        assert not r23.check("cb.yaml", doc).passed

    def test_builtin_subs_dont_trip(self):
        # Built-in substitutions don't use leading underscore so the
        # regex doesn't match them at all — but the user-shaped
        # built-ins (_HEAD_BRANCH etc) need allow-listing.
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["build", "-t", "$_HEAD_BRANCH", "."],
        }])
        assert r23.check("cb.yaml", doc).passed

    def test_no_steps_passes(self):
        assert r23.check("cb.yaml", _doc()).passed

    def test_walks_entrypoint_dir_env(self):
        doc = _doc(steps=[{
            "name": "ubuntu",
            "entrypoint": "bash",
            "args": ["-c", "echo $_FOO"],
        }])
        f = r23.check("cb.yaml", doc)
        assert not f.passed
        assert "_FOO" in f.description


# ──────────────────────────────────────────────────────────────────
# GCB-024 — images: missing despite docker push
# ──────────────────────────────────────────────────────────────────


class TestGCB024ImagesMissing:
    def test_fails_when_push_step_no_images_declared(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["push", "gcr.io/myproject/myapp:v1"],
        }])
        f = r24.check("cb.yaml", doc)
        assert not f.passed
        assert "step[0]" in f.description

    def test_passes_when_images_declared(self):
        doc = _doc(
            steps=[{
                "name": "gcr.io/cloud-builders/docker",
                "args": ["push", "gcr.io/myproject/myapp:v1"],
            }],
            images=["gcr.io/myproject/myapp:v1"],
        )
        assert r24.check("cb.yaml", doc).passed

    def test_passes_when_no_push_step(self):
        # Steps that only build (and don't push) don't trip the rule.
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["build", "-t", "myapp:v1", "."],
        }])
        assert r24.check("cb.yaml", doc).passed

    def test_buildx_push_flag_detected(self):
        doc = _doc(steps=[{
            "name": "gcr.io/cloud-builders/docker",
            "args": ["buildx", "build", "--push", "-t", "x", "."],
        }])
        assert not r24.check("cb.yaml", doc).passed

    def test_empty_images_list_fails(self):
        doc = _doc(
            steps=[{
                "name": "gcr.io/cloud-builders/docker",
                "args": ["push", "gcr.io/myproject/myapp:v1"],
            }],
            images=[],
        )
        assert not r24.check("cb.yaml", doc).passed


# ──────────────────────────────────────────────────────────────────
# GCB-025 — tags: empty
# ──────────────────────────────────────────────────────────────────


class TestGCB025TagsEmpty:
    def test_passes_when_tags_populated(self):
        assert r25.check("cb.yaml", _doc(tags=["prod", "backend"])).passed

    def test_fails_when_tags_missing(self):
        assert not r25.check("cb.yaml", _doc()).passed

    def test_fails_when_tags_empty_list(self):
        assert not r25.check("cb.yaml", _doc(tags=[])).passed

    def test_fails_when_tags_only_blank_strings(self):
        assert not r25.check("cb.yaml", _doc(tags=["", "  "])).passed

    def test_substitution_bearing_tag_counts(self):
        # ``$BRANCH_NAME`` expands at submission time → counts as
        # populated for audit purposes.
        assert r25.check("cb.yaml", _doc(tags=["$BRANCH_NAME"])).passed


# ──────────────────────────────────────────────────────────────────
# GCB-026 — waitFor references unknown id
# ──────────────────────────────────────────────────────────────────


class TestGCB026WaitForDangling:
    def test_passes_when_waitfor_references_known_id(self):
        doc = _doc(steps=[
            {"name": "ubuntu", "id": "setup", "args": ["true"]},
            {"name": "ubuntu", "args": ["true"], "waitFor": ["setup"]},
        ])
        assert r26.check("cb.yaml", doc).passed

    def test_fails_when_waitfor_references_unknown_id(self):
        doc = _doc(steps=[
            {"name": "ubuntu", "id": "setup", "args": ["true"]},
            {"name": "ubuntu", "args": ["true"], "waitFor": ["typo-here"]},
        ])
        f = r26.check("cb.yaml", doc)
        assert not f.passed
        assert "typo-here" in f.description

    def test_dash_sentinel_passes(self):
        doc = _doc(steps=[
            {"name": "ubuntu", "args": ["true"], "waitFor": ["-"]},
        ])
        assert r26.check("cb.yaml", doc).passed

    def test_no_waitfor_passes(self):
        doc = _doc(steps=[{"name": "ubuntu", "args": ["true"]}])
        assert r26.check("cb.yaml", doc).passed

    def test_one_known_one_unknown_fails(self):
        doc = _doc(steps=[
            {"name": "ubuntu", "id": "setup", "args": ["true"]},
            {"name": "ubuntu", "args": ["true"],
             "waitFor": ["setup", "typo"]},
        ])
        assert not r26.check("cb.yaml", doc).passed

    def test_empty_string_in_waitfor_tolerated(self):
        # Empty entries are ignored (Cloud Build itself tolerates).
        doc = _doc(steps=[
            {"name": "ubuntu", "args": ["true"], "waitFor": [""]},
        ])
        assert r26.check("cb.yaml", doc).passed
