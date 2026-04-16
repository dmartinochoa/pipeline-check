"""End-to-end parser tests — real-world CI YAML fixtures for every workflow
provider (GitHub Actions, GitLab CI, Bitbucket Pipelines).

For each provider, a paired ``insecure`` / ``secure`` fixture is scanned
through the full provider stack (context loader → check class → Finding).
The insecure fixture is asserted to fail every check; the secure fixture
is asserted to pass every check. This catches regressions in both the
YAML loaders and the individual check implementations.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks
from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks

FIXTURES = Path(__file__).parent / "fixtures" / "workflows"


def _finding_map(findings):
    """Return {check_id: passed} dict for fast assertion."""
    return {f.check_id: f.passed for f in findings}


# ────────────────────────────────────────────────────────────────────────────
# GitHub Actions
# ────────────────────────────────────────────────────────────────────────────


class TestGitHubFixtures:
    EXPECTED_IDS = {f"GHA-{i:03d}" for i in range(1, 21)}

    def _scan(self, filename: str):
        ctx = GitHubContext.from_path(FIXTURES / "github" / filename)
        assert ctx.workflows, f"fixture {filename} produced no parsed workflows"
        return _finding_map(WorkflowChecks(ctx).run())

    def test_insecure_release_fails_every_check(self):
        results = self._scan("insecure-release.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every GHA check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_release_passes_every_check(self):
        results = self._scan("secure-release.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every GHA check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# GitLab CI
# ────────────────────────────────────────────────────────────────────────────


class TestGitLabFixtures:
    EXPECTED_IDS = {f"GL-{i:03d}" for i in range(1, 21)}

    def _scan(self, filename: str):
        ctx = GitLabContext.from_path(FIXTURES / "gitlab" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed pipelines"
        return _finding_map(GitLabPipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure.gitlab-ci.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every GL check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure.gitlab-ci.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every GL check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Bitbucket Pipelines
# ────────────────────────────────────────────────────────────────────────────


class TestBitbucketFixtures:
    EXPECTED_IDS = {f"BB-{i:03d}" for i in range(1, 21)}

    def _scan(self, filename: str):
        ctx = BitbucketContext.from_path(FIXTURES / "bitbucket" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed pipelines"
        return _finding_map(BitbucketPipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-bitbucket-pipelines.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every BB check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-bitbucket-pipelines.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every BB check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Azure DevOps Pipelines
# ────────────────────────────────────────────────────────────────────────────


class TestAzureFixtures:
    EXPECTED_IDS = {f"ADO-{i:03d}" for i in range(1, 21)}

    def _scan(self, filename: str):
        ctx = AzureContext.from_path(FIXTURES / "azure" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed pipelines"
        return _finding_map(AzurePipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-azure-pipelines.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS

    def test_secure_passes_every_check(self):
        results = self._scan("secure-azure-pipelines.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS


# ────────────────────────────────────────────────────────────────────────────
# Jenkins
# ────────────────────────────────────────────────────────────────────────────


class TestJenkinsFixtures:
    EXPECTED_IDS = {f"JF-{i:03d}" for i in range(1, 21)}

    def _scan(self, filename: str):
        ctx = JenkinsContext.from_path(FIXTURES / "jenkins" / filename)
        assert ctx.files, f"fixture {filename} produced no parsed Jenkinsfiles"
        return _finding_map(JenkinsfileChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("Jenkinsfile.insecure")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every JF check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("Jenkinsfile.secure")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every JF check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Cross-provider sanity — findings carry control refs from enabled standards
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("provider,fixture,loader,checker,expected", [
    ("github", "github/insecure-release.yml", GitHubContext, WorkflowChecks,
     {f"GHA-{i:03d}" for i in range(1, 21)}),
    ("gitlab", "gitlab/insecure.gitlab-ci.yml", GitLabContext, GitLabPipelineChecks,
     {f"GL-{i:03d}" for i in range(1, 21)}),
    ("bitbucket", "bitbucket/insecure-bitbucket-pipelines.yml",
     BitbucketContext, BitbucketPipelineChecks,
     {f"BB-{i:03d}" for i in range(1, 21)}),
    ("azure", "azure/insecure-azure-pipelines.yml",
     AzureContext, AzurePipelineChecks,
     {f"ADO-{i:03d}" for i in range(1, 21)}),
    ("jenkins", "jenkins/Jenkinsfile.insecure", JenkinsContext, JenkinsfileChecks,
     {f"JF-{i:03d}" for i in range(1, 21)}),
])
def test_every_insecure_fixture_emits_expected_check_ids(
    provider, fixture, loader, checker, expected
):
    """Each insecure fixture emits exactly the expected set of check IDs
    (no missing checks, no phantom ones)."""
    ctx = loader.from_path(FIXTURES / fixture)
    emitted = {f.check_id for f in checker(ctx).run()}
    assert emitted == expected, (
        f"[{provider}] check IDs differ: "
        f"missing={expected - emitted}, extra={emitted - expected}"
    )
