"""IAM-009 / IAM-010: Azure + GCP workload-identity-federation OIDC trust."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.rules import (
    iam009_azure_oidc_subject as azure_rule,
)
from pipeline_check.core.checks.terraform.rules import (
    iam010_gcp_wif_attribute_condition as gcp_rule,
)

_GH_ISSUER = "https://token.actions.githubusercontent.com"


def _ctx(resource):
    plan = {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": [resource], "child_modules": []}}}
    return TerraformContext(plan)


def _azure_cred(subject, issuer=_GH_ISSUER):
    return {
        "address": "azurerm_federated_identity_credential.gh",
        "mode": "managed", "type": "azurerm_federated_identity_credential",
        "name": "gh",
        "values": {"issuer": issuer, "subject": subject},
    }


def _gcp_provider(attribute_condition=None, issuer=_GH_ISSUER, oidc=True):
    values = {}
    if oidc:
        values["oidc"] = [{"issuer_uri": issuer}]
    else:
        values["aws"] = [{"account_id": "123456789012"}]
    if attribute_condition is not None:
        values["attribute_condition"] = attribute_condition
    return {
        "address": "google_iam_workload_identity_pool_provider.gh",
        "mode": "managed",
        "type": "google_iam_workload_identity_pool_provider",
        "name": "gh", "values": values,
    }


class TestIAM009AzureSubject:
    def test_pull_request_subject_fails(self):
        f = azure_rule.check(_ctx(_azure_cred("repo:myorg/myrepo:pull_request")))[0]
        assert not f.passed

    def test_org_wildcard_subject_fails(self):
        f = azure_rule.check(_ctx(_azure_cred("repo:myorg/*:ref:refs/heads/main")))[0]
        assert not f.passed

    def test_ref_wildcard_subject_fails(self):
        f = azure_rule.check(_ctx(_azure_cred("repo:myorg/myrepo:*")))[0]
        assert not f.passed

    def test_pinned_branch_subject_passes(self):
        f = azure_rule.check(_ctx(_azure_cred("repo:myorg/myrepo:ref:refs/heads/main")))[0]
        assert f.passed

    def test_pinned_environment_subject_passes(self):
        f = azure_rule.check(_ctx(_azure_cred("repo:myorg/myrepo:environment:production")))[0]
        assert f.passed

    def test_non_github_issuer_skipped(self):
        # A GitLab-issuer credential uses a different subject grammar;
        # this rule scopes itself to the GitHub claim shape.
        cred = _azure_cred("project_path:grp/proj:ref_type:branch:ref:main",
                           issuer="https://gitlab.com")
        assert azure_rule.check(_ctx(cred)) == []


class TestIAM010GcpAttributeCondition:
    def test_missing_condition_fails(self):
        f = gcp_rule.check(_ctx(_gcp_provider(attribute_condition=None)))[0]
        assert not f.passed

    def test_empty_condition_fails(self):
        f = gcp_rule.check(_ctx(_gcp_provider(attribute_condition="   ")))[0]
        assert not f.passed

    def test_condition_without_repo_constraint_fails(self):
        # Constrains only the audience, never the source repository.
        f = gcp_rule.check(_ctx(_gcp_provider(
            attribute_condition="assertion.aud == 'prod'")))[0]
        assert not f.passed

    def test_repository_owner_condition_passes(self):
        f = gcp_rule.check(_ctx(_gcp_provider(
            attribute_condition="assertion.repository_owner == 'myorg'")))[0]
        assert f.passed

    def test_repository_condition_passes(self):
        f = gcp_rule.check(_ctx(_gcp_provider(
            attribute_condition="assertion.repository == 'myorg/myrepo'")))[0]
        assert f.passed

    def test_non_oidc_provider_skipped(self):
        # An aws-block provider has no OIDC issuer to over-trust.
        assert gcp_rule.check(_ctx(_gcp_provider(oidc=False))) == []

    def test_non_ci_issuer_with_condition_passes(self):
        # A bespoke OIDC issuer with any condition is left alone; only the
        # missing-condition case is universal.
        f = gcp_rule.check(_ctx(_gcp_provider(
            attribute_condition="assertion.email == 'ci@example.com'",
            issuer="https://oidc.example.com")))[0]
        assert f.passed

    def test_non_ci_issuer_missing_condition_fails(self):
        f = gcp_rule.check(_ctx(_gcp_provider(
            attribute_condition=None, issuer="https://oidc.example.com")))[0]
        assert not f.passed
