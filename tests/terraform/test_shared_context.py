"""Tests for the shared rule-context helpers under
``terraform/rules/_iam_context.py`` and ``_s3_context.py``.

These helpers are underscore-prefixed so :func:`discover_rules` skips
them, which means the per-rule tests don't pull them into coverage
when the surrounding rules short-circuit. Exercising the helpers
directly locks in the path-merging semantics that the new rule modules
depend on (managed/attached/inline policy walking, artifact-bucket
discovery).
"""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.rules._iam_context import (
    _role_is_cicd,
    cicd_role_view,
)
from pipeline_check.core.checks.terraform.rules._s3_context import (
    artifact_buckets,
    index_by_bucket,
)

_CB_TRUST = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_CB_TRUST_LIST_SERVICES = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "Service": ["codedeploy.amazonaws.com", "ec2.amazonaws.com"],
        },
        "Action": "sts:AssumeRole",
    }],
})
_NON_CICD_TRUST = json.dumps({
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _plan(resources):
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {"resources": resources, "child_modules": []},
        },
    }


def _role(name, trust=_CB_TRUST, **kw):
    vals = {"name": name, "assume_role_policy": trust}
    vals.update(kw)
    return {
        "address": f"aws_iam_role.{name}",
        "mode": "managed", "type": "aws_iam_role", "name": name,
        "values": vals,
    }


def _attach(role, arn):
    return {
        "address": f"aws_iam_role_policy_attachment.{role}",
        "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": role,
        "values": {"role": role, "policy_arn": arn},
    }


def _inline_separate(role, pname, doc):
    return {
        "address": f"aws_iam_role_policy.{role}",
        "mode": "managed", "type": "aws_iam_role_policy", "name": pname,
        "values": {"role": role, "name": pname, "policy": json.dumps(doc)},
    }


def _customer_policy(name, arn, doc):
    return {
        "address": f"aws_iam_policy.{name}",
        "mode": "managed", "type": "aws_iam_policy", "name": name,
        "values": {"name": name, "arn": arn, "policy": json.dumps(doc)},
    }


# ── _role_is_cicd ──────────────────────────────────────────────────


class TestRoleIsCicd:
    def test_codebuild_principal_string_form_matches(self):
        assert _role_is_cicd({"assume_role_policy": _CB_TRUST}) is True

    def test_codedeploy_principal_in_list_matches(self):
        # Principal.Service supports both a string and a list of strings
        # per AWS docs; both forms must classify as CI/CD when any
        # member is in the CICD set.
        assert _role_is_cicd({"assume_role_policy": _CB_TRUST_LIST_SERVICES}) is True

    def test_non_cicd_principal_rejected(self):
        assert _role_is_cicd({"assume_role_policy": _NON_CICD_TRUST}) is False

    def test_missing_trust_doc_treated_as_not_cicd(self):
        # No assume_role_policy attr at all (parse_doc returns {}).
        assert _role_is_cicd({}) is False

    def test_empty_principal_block_safely_handled(self):
        # Principal is an empty dict; .get(..., {}) returns {} and the
        # loop produces no candidates.
        doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {}}]})
        assert _role_is_cicd({"assume_role_policy": doc}) is False

    def test_null_principal_block_safely_handled(self):
        # Principal explicitly null in the doc; the "{} or {}" trick
        # short-circuits to {}.
        doc = json.dumps([
            {"Statement": [{"Effect": "Allow", "Principal": None}]}
        ][0])
        assert _role_is_cicd({"assume_role_policy": doc}) is False


# ── cicd_role_view ─────────────────────────────────────────────────


class TestCicdRoleViewEmptyShortCircuit:
    def test_no_cicd_roles_returns_empty(self):
        ctx = TerraformContext(_plan([
            _role("r", trust=_NON_CICD_TRUST),
        ]))
        assert cicd_role_view(ctx) == []

    def test_no_roles_at_all_returns_empty(self):
        ctx = TerraformContext(_plan([]))
        assert cicd_role_view(ctx) == []


class TestCicdRoleViewManagedArns:
    def test_managed_policy_arns_inlined_on_role_surface(self):
        # Both forms (inline on the role vs separate attachment)
        # should produce the same managed_arns list once enumerated.
        ctx = TerraformContext(_plan([
            _role("r", managed_policy_arns=[
                "arn:aws:iam::aws:policy/AdministratorAccess",
            ]),
        ]))
        view = cicd_role_view(ctx)
        assert len(view) == 1
        _, managed_arns, _ = view[0]
        assert "arn:aws:iam::aws:policy/AdministratorAccess" in managed_arns

    def test_attachment_resource_joined_by_role_name(self):
        ctx = TerraformContext(_plan([
            _role("ci-builder"),
            _attach("ci-builder", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            _attach("ci-builder", "arn:aws:iam::aws:policy/PowerUserAccess"),
            # Attachment whose role name doesn't match any role; ignored.
            _attach("orphan", "arn:aws:iam::aws:policy/NeverSeen"),
        ]))
        view = cicd_role_view(ctx)
        assert len(view) == 1
        _, managed_arns, _ = view[0]
        assert set(managed_arns) == {
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
        }

    def test_attachment_with_blank_role_or_arn_skipped(self):
        # Skip attachments where either side is empty — the index
        # would otherwise pollute the wrong role's view.
        ctx = TerraformContext(_plan([
            _role("ci"),
            {
                "address": "aws_iam_role_policy_attachment.bad",
                "mode": "managed", "type": "aws_iam_role_policy_attachment",
                "name": "bad",
                "values": {"role": "", "policy_arn": "arn:aws:iam::aws:policy/Z"},
            },
            {
                "address": "aws_iam_role_policy_attachment.empty",
                "mode": "managed", "type": "aws_iam_role_policy_attachment",
                "name": "empty",
                "values": {"role": "ci", "policy_arn": ""},
            },
        ]))
        view = cicd_role_view(ctx)
        assert len(view) == 1
        _, managed_arns, _ = view[0]
        assert managed_arns == []

    def test_managed_arn_falls_back_to_resource_name_when_name_attr_missing(self):
        # Roles can omit the ``name`` attribute (Terraform generates one);
        # the helper falls back to the resource label so attachments
        # joined on the resource label still match.
        ctx = TerraformContext(_plan([
            {
                "address": "aws_iam_role.ci",
                "mode": "managed", "type": "aws_iam_role", "name": "ci",
                "values": {"assume_role_policy": _CB_TRUST},  # no name
            },
            _attach("ci", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
        ]))
        view = cicd_role_view(ctx)
        _, managed_arns, _ = view[0]
        assert "arn:aws:iam::aws:policy/ReadOnlyAccess" in managed_arns


class TestCicdRoleViewPolicyDocs:
    def test_inline_separate_policy_doc_attached(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ctx = TerraformContext(_plan([
            _role("ci"),
            _inline_separate("ci", "bad-policy", doc),
        ]))
        view = cicd_role_view(ctx)
        _, _, docs = view[0]
        assert len(docs) == 1
        name, parsed = docs[0]
        assert name == "bad-policy"
        assert parsed == doc

    def test_inline_separate_with_blank_role_skipped(self):
        # aws_iam_role_policy with no role assignment shouldn't be
        # mis-attached to anyone.
        ctx = TerraformContext(_plan([
            _role("ci"),
            {
                "address": "aws_iam_role_policy.orphan",
                "mode": "managed", "type": "aws_iam_role_policy", "name": "x",
                "values": {"role": "", "name": "x", "policy": "{}"},
            },
        ]))
        _, _, docs = cicd_role_view(ctx)[0]
        assert docs == []

    def test_inline_separate_falls_back_to_resource_label_for_pname(self):
        doc = {"Statement": []}
        ctx = TerraformContext(_plan([
            _role("ci"),
            {
                "address": "aws_iam_role_policy.label-only",
                "mode": "managed", "type": "aws_iam_role_policy",
                "name": "label-only",
                # no "name" key inside values — should fall back to
                # the resource label "label-only".
                "values": {"role": "ci", "policy": json.dumps(doc)},
            },
        ]))
        _, _, docs = cicd_role_view(ctx)[0]
        assert docs == [("label-only", doc)]

    def test_inline_policy_block_attached(self):
        # The deprecated ``inline_policy`` block on aws_iam_role itself
        # still has to be discoverable so old configs don't get a
        # false-pass.
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]}
        ctx = TerraformContext(_plan([
            _role("ci", inline_policy=[
                {"name": "embedded", "policy": json.dumps(doc)},
            ]),
        ]))
        _, _, docs = cicd_role_view(ctx)[0]
        assert ("embedded", doc) in docs

    def test_inline_policy_block_without_name_uses_default_label(self):
        doc = {"Statement": []}
        ctx = TerraformContext(_plan([
            _role("ci", inline_policy=[{"policy": json.dumps(doc)}]),
        ]))
        _, _, docs = cicd_role_view(ctx)[0]
        # No "name" → labeled "inline".
        assert docs[0][0] == "inline"

    def test_customer_managed_policy_joined_via_attachment(self):
        # aws_iam_policy is the customer-managed kind; its document
        # only appears in the view when the role attaches it by ARN.
        doc = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt"}]}
        ctx = TerraformContext(_plan([
            _role("ci"),
            _attach("ci", "arn:aws:iam::111:policy/team-decrypt"),
            _customer_policy(
                "team_decrypt",
                "arn:aws:iam::111:policy/team-decrypt",
                doc,
            ),
        ]))
        _, managed_arns, docs = cicd_role_view(ctx)[0]
        assert "arn:aws:iam::111:policy/team-decrypt" in managed_arns
        # Doc surfaces under the ARN key (so the rule can dedupe by
        # ARN if it cares).
        assert ("arn:aws:iam::111:policy/team-decrypt", doc) in docs

    def test_customer_managed_policy_not_in_view_without_attachment(self):
        # Defining an aws_iam_policy that nobody attaches must NOT
        # cause it to be evaluated against an unrelated role.
        doc = {"Statement": [{"Effect": "Allow", "Action": "*"}]}
        ctx = TerraformContext(_plan([
            _role("ci"),
            _customer_policy(
                "loose", "arn:aws:iam::111:policy/loose", doc,
            ),
        ]))
        _, _, docs = cicd_role_view(ctx)[0]
        assert docs == []

    def test_customer_policy_without_arn_safely_skipped(self):
        # aws_iam_policy missing the arn attr (rare — Terraform usually
        # populates it) must not enter the lookup map and crash.
        ctx = TerraformContext(_plan([
            _role("ci"),
            {
                "address": "aws_iam_policy.no_arn",
                "mode": "managed", "type": "aws_iam_policy", "name": "p",
                "values": {"name": "p", "policy": "{}"},  # no arn
            },
        ]))
        # Should not raise and should return an empty docs list.
        _, _, docs = cicd_role_view(ctx)[0]
        assert docs == []

    def test_multi_role_partitioning(self):
        # Two CI/CD roles + one non-CI/CD role. Each CI/CD role only
        # sees its own attached policies — no cross-contamination.
        ctx = TerraformContext(_plan([
            _role("alpha"),
            _role("beta"),
            _role("ec2", trust=_NON_CICD_TRUST),
            _attach("alpha", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            _attach("beta", "arn:aws:iam::aws:policy/PowerUserAccess"),
        ]))
        view = cicd_role_view(ctx)
        assert len(view) == 2
        by_role = {r.name: arns for r, arns, _ in view}
        assert by_role["alpha"] == ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        assert by_role["beta"] == ["arn:aws:iam::aws:policy/PowerUserAccess"]


# ── artifact_buckets / index_by_bucket ─────────────────────────────


class TestS3ContextArtifactBuckets:
    def test_collects_locations_from_artifact_stores(self):
        ctx = TerraformContext(_plan([
            {
                "address": "aws_codepipeline.app",
                "mode": "managed", "type": "aws_codepipeline", "name": "app",
                "values": {
                    "artifact_store": [
                        {"type": "S3", "location": "ci-art-prod"},
                        {"type": "S3", "location": "ci-art-dr"},
                    ],
                },
            },
        ]))
        assert artifact_buckets(ctx) == {"ci-art-prod", "ci-art-dr"}

    def test_no_pipelines_returns_empty_set(self):
        ctx = TerraformContext(_plan([]))
        assert artifact_buckets(ctx) == set()

    def test_pipeline_with_no_artifact_store_block_safely_handled(self):
        ctx = TerraformContext(_plan([
            {
                "address": "aws_codepipeline.empty",
                "mode": "managed", "type": "aws_codepipeline", "name": "empty",
                "values": {},
            },
        ]))
        assert artifact_buckets(ctx) == set()

    def test_artifact_store_without_location_skipped(self):
        # ``location`` is optional in the Terraform schema; missing /
        # empty entries must not pollute the bucket set.
        ctx = TerraformContext(_plan([
            {
                "address": "aws_codepipeline.app",
                "mode": "managed", "type": "aws_codepipeline", "name": "app",
                "values": {
                    "artifact_store": [
                        {"type": "S3"},                # no location
                        {"type": "S3", "location": ""},  # empty location
                        {"type": "S3", "location": "real-bucket"},
                    ],
                },
            },
        ]))
        assert artifact_buckets(ctx) == {"real-bucket"}

    def test_null_artifact_store_field_safe(self):
        # Pipeline with the field explicitly null (rare but legal).
        ctx = TerraformContext(_plan([
            {
                "address": "aws_codepipeline.app",
                "mode": "managed", "type": "aws_codepipeline", "name": "app",
                "values": {"artifact_store": None},
            },
        ]))
        assert artifact_buckets(ctx) == set()


class TestS3ContextIndexByBucket:
    def test_indexes_by_bucket_attr(self):
        ctx = TerraformContext(_plan([
            {
                "address": "aws_s3_bucket_versioning.v",
                "mode": "managed", "type": "aws_s3_bucket_versioning",
                "name": "v",
                "values": {
                    "bucket": "ci-art-prod",
                    "versioning_configuration": [{"status": "Enabled"}],
                },
            },
            {
                "address": "aws_s3_bucket_versioning.v2",
                "mode": "managed", "type": "aws_s3_bucket_versioning",
                "name": "v2",
                "values": {
                    "bucket": "ci-art-dr",
                    "versioning_configuration": [{"status": "Disabled"}],
                },
            },
        ]))
        idx = index_by_bucket(ctx, "aws_s3_bucket_versioning")
        assert set(idx) == {"ci-art-prod", "ci-art-dr"}
        assert (
            idx["ci-art-prod"]["versioning_configuration"][0]["status"]
            == "Enabled"
        )

    def test_resource_without_bucket_attr_skipped(self):
        ctx = TerraformContext(_plan([
            {
                "address": "aws_s3_bucket_versioning.bad",
                "mode": "managed", "type": "aws_s3_bucket_versioning",
                "name": "bad",
                "values": {},  # no bucket attr
            },
        ]))
        assert index_by_bucket(ctx, "aws_s3_bucket_versioning") == {}

    def test_unrelated_type_returns_empty_index(self):
        ctx = TerraformContext(_plan([
            {
                "address": "aws_s3_bucket.b",
                "mode": "managed", "type": "aws_s3_bucket", "name": "b",
                "values": {"bucket": "x"},
            },
        ]))
        # Looking up a type that doesn't exist in the plan returns
        # an empty dict, not a crash.
        assert index_by_bucket(ctx, "aws_s3_bucket_versioning") == {}

    def test_later_resource_wins_on_duplicate_bucket(self):
        # Two same-bucket resources of the same type — last one wins
        # (dict insertion-order overwrite). Locks the behavior so a
        # future "warn on duplicate" refactor has to revisit this.
        ctx = TerraformContext(_plan([
            {
                "address": "aws_s3_bucket_versioning.first",
                "mode": "managed", "type": "aws_s3_bucket_versioning",
                "name": "first",
                "values": {"bucket": "ci", "marker": "first"},
            },
            {
                "address": "aws_s3_bucket_versioning.second",
                "mode": "managed", "type": "aws_s3_bucket_versioning",
                "name": "second",
                "values": {"bucket": "ci", "marker": "second"},
            },
        ]))
        idx = index_by_bucket(ctx, "aws_s3_bucket_versioning")
        assert idx["ci"]["marker"] == "second"
