"""Per-rule tests for Azure DevOps pinning and template-handling rules:
ADO-009 (container image pinned by tag rather than sha256 digest),
ADO-011 (``template:`` local-path on PR-validated pipeline),
ADO-019 (``extends:`` template local-path on PR-validated pipeline),
ADO-029 (service-connection-using job without environment / branch gate).

ADO-005 fails floating tags at HIGH; ADO-009 is the stricter
sha256 tier. ADO-011 / ADO-019 cover the two template-include
shapes that PR authors can poison. ADO-029 is the workload-identity
deploy gate analogous to GHA-030.
"""
from __future__ import annotations

from .conftest import run_check

# ── ADO-009 container image digest pinning ──────────────────────────


class TestADO009DigestPinning:
    def test_fails_when_container_pinned_by_version_tag(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        jobs:
          - job: build
            container: cimg/python:3.12.1
            steps:
              - script: pytest
        """
        f = run_check(cfg, "ADO-009")
        assert not f.passed

    def test_passes_when_container_pinned_by_digest(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        jobs:
          - job: build
            container: cimg/python@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - script: pytest
        """
        f = run_check(cfg, "ADO-009")
        assert f.passed


# ── ADO-011 local template on PR pipeline ───────────────────────────


class TestADO011LocalTemplateOnPR:
    def test_fails_on_local_template_with_pr_trigger(self):
        cfg = """
        pr:
          branches:
            include: [main]
        pool: {vmImage: ubuntu-latest}
        steps:
          - template: shared/build.yml
        """
        f = run_check(cfg, "ADO-011")
        assert not f.passed

    def test_passes_with_cross_repo_template(self):
        cfg = """
        pr:
          branches:
            include: [main]
        resources:
          repositories:
            - repository: tools
              type: git
              name: org/tools
              ref: aabbccddeeff00112233445566778899aabbccdd
        pool: {vmImage: ubuntu-latest}
        steps:
          - template: build.yml@tools
        """
        f = run_check(cfg, "ADO-011")
        assert f.passed

    def test_passes_when_no_pr_trigger(self):
        # Push-only pipeline — local template is fine because the PR
        # author can't influence which commit the template comes from.
        cfg = """
        trigger:
          branches:
            include: [main]
        pool: {vmImage: ubuntu-latest}
        steps:
          - template: shared/build.yml
        """
        f = run_check(cfg, "ADO-011")
        assert f.passed


# ── ADO-019 local extends template on PR pipeline ───────────────────


class TestADO019ExtendsInjection:
    def test_fails_on_local_extends_with_pr_trigger(self):
        cfg = """
        pr:
          branches:
            include: [main]
        extends:
          template: shared/release.yml
        """
        f = run_check(cfg, "ADO-019")
        assert not f.passed

    def test_passes_with_cross_repo_extends(self):
        cfg = """
        pr:
          branches:
            include: [main]
        resources:
          repositories:
            - repository: shared
              type: git
              name: org/shared
              ref: aabbccddeeff00112233445566778899aabbccdd
        extends:
          template: release.yml@shared
        """
        f = run_check(cfg, "ADO-019")
        assert f.passed


# ── ADO-029 OIDC / service connection without environment ───────────


class TestADO029OIDCTrust:
    def test_fails_when_azurecli_lacks_environment(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - task: AzureCLI@2
            inputs:
              azureSubscription: prod-sc
              scriptType: bash
              inlineScript: az group list
        """
        f = run_check(cfg, "ADO-029")
        assert not f.passed

    def test_passes_when_azurecli_runs_in_environment_job(self):
        cfg = """
        jobs:
          - deployment: deploy
            environment: production
            pool: {vmImage: ubuntu-latest}
            strategy:
              runOnce:
                deploy:
                  steps:
                    - task: AzureCLI@2
                      inputs:
                        azureSubscription: prod-sc
                        scriptType: bash
                        inlineScript: az group list
        """
        f = run_check(cfg, "ADO-029")
        assert f.passed

    def test_passes_when_no_service_connection_task(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: make test
        """
        f = run_check(cfg, "ADO-029")
        assert f.passed
