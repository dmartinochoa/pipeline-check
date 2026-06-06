"""End-to-end parser tests — real-world CI YAML fixtures for every workflow
provider (GitHub Actions, GitLab CI, Bitbucket Pipelines).

For each provider, a paired ``insecure`` / ``secure`` fixture is scanned
through the full provider stack (context loader → check class → Finding).
The insecure fixture is asserted to fail every check; the secure fixture
is asserted to pass every check. This catches regressions in both the
YAML loaders and the individual check implementations.
"""
from __future__ import annotations

from datetime import UTC
from pathlib import Path

import pytest

from pipeline_check.core.checks.argo.base import ArgoContext
from pipeline_check.core.checks.argo.pipelines import ArgoChecks
from pipeline_check.core.checks.azure.base import AzureContext
from pipeline_check.core.checks.azure.pipelines import AzurePipelineChecks
from pipeline_check.core.checks.bitbucket.base import BitbucketContext
from pipeline_check.core.checks.bitbucket.pipelines import BitbucketPipelineChecks
from pipeline_check.core.checks.buildkite.base import BuildkiteContext
from pipeline_check.core.checks.buildkite.pipelines import BuildkitePipelineChecks
from pipeline_check.core.checks.circleci.base import CircleCIContext
from pipeline_check.core.checks.circleci.pipelines import CircleCIPipelineChecks
from pipeline_check.core.checks.cloudbuild.base import CloudBuildContext
from pipeline_check.core.checks.cloudbuild.pipelines import CloudBuildPipelineChecks
from pipeline_check.core.checks.dockerfile.base import DockerfileContext
from pipeline_check.core.checks.dockerfile.pipelines import DockerfileChecks
from pipeline_check.core.checks.github.base import GitHubContext
from pipeline_check.core.checks.github.workflows import WorkflowChecks
from pipeline_check.core.checks.gitlab.base import GitLabContext
from pipeline_check.core.checks.gitlab.pipelines import GitLabPipelineChecks
from pipeline_check.core.checks.jenkins.base import JenkinsContext
from pipeline_check.core.checks.jenkins.jenkinsfile import JenkinsfileChecks
from pipeline_check.core.checks.kubernetes.base import KubernetesContext
from pipeline_check.core.checks.kubernetes.manifests import KubernetesManifestChecks
from pipeline_check.core.checks.tekton.base import TektonContext
from pipeline_check.core.checks.tekton.pipelines import TektonChecks

FIXTURES = Path(__file__).parent / "fixtures" / "workflows"


def _finding_map(findings):
    """Return {check_id: passed} dict for fast assertion."""
    return {f.check_id: f.passed for f in findings}


# ────────────────────────────────────────────────────────────────────────────
# GitHub Actions
# ────────────────────────────────────────────────────────────────────────────


class TestGitHubFixtures:
    EXPECTED_IDS = (
        # GHA-062 (sibling-IaC OIDC subject) needs an on-disk
        # trust-policy.json next to the workflow; tested in
        # tests/github/test_gha062.py with per-case tmpdir fixtures
        # rather than the shared insecure/secure pair, so it's
        # excluded from this all-rules-fire / no-rules-fire contract.
        ({f"GHA-{i:03d}" for i in range(1, 63)} - {"GHA-062"})
        | {"TAINT-001", "TAINT-002", "TAINT-003"}
    )

    def _scan(self, filename: str):
        from datetime import datetime, timedelta

        from pipeline_check.core.checks.github._action_reputation import (
            ActionRepoMetadata,
            collect_referenced_action_refs,
            collect_referenced_actions,
        )

        ctx = GitHubContext.from_path(FIXTURES / "github" / filename)
        assert ctx.workflows, f"fixture {filename} produced no parsed workflows"

        # The GHA-04x reputation rules read ``ctx.action_metadata``;
        # populate it synthetically here so the secure / insecure
        # contract extends to the reputation pack. "insecure" fixtures
        # mark every action as single-maintainer / very-young / low-
        # star so all three rules fire; "secure" fixtures mark every
        # action as well-maintained / aged / popular so all three pass.
        # GHA-047 additionally reads per-ref commit dates from
        # ``ref_committed_at``; insecure refs land a recent (fresh)
        # date so the cooldown rule fires, secure refs land an old
        # date so it passes.
        is_secure = filename.startswith("secure")
        if is_secure:
            repo_now = datetime.now(tz=UTC) - timedelta(days=1000)
            ref_now = datetime.now(tz=UTC) - timedelta(days=180)
            template = ActionRepoMetadata(
                owner="x", repo="y",
                contributor_count=42,
                created_at=repo_now.replace(microsecond=0).isoformat().replace(
                    "+00:00", "Z",
                ),
                stargazers_count=5000,
                owner_type="Organization",
            )
        else:
            repo_now = datetime.now(tz=UTC) - timedelta(days=10)
            ref_now = datetime.now(tz=UTC) - timedelta(days=1)
            template = ActionRepoMetadata(
                owner="x", repo="y",
                contributor_count=1,
                created_at=repo_now.replace(microsecond=0).isoformat().replace(
                    "+00:00", "Z",
                ),
                stargazers_count=2,
                owner_type="User",
            )
        ref_iso = ref_now.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z",
        )
        refs_by_action = collect_referenced_action_refs(ctx)
        meta: dict[str, ActionRepoMetadata] = {}
        for owner, repo in collect_referenced_actions(ctx):
            refs = refs_by_action.get((owner, repo), set())
            ref_dates = dict.fromkeys(refs, ref_iso) if refs else None
            meta[f"{owner}/{repo}"] = ActionRepoMetadata(
                owner=owner, repo=repo,
                contributor_count=template.contributor_count,
                created_at=template.created_at,
                stargazers_count=template.stargazers_count,
                owner_type=template.owner_type,
                ref_committed_at=ref_dates,
            )
        ctx.action_metadata = meta
        return _finding_map(WorkflowChecks(ctx).run())

    def test_insecure_release_fails_every_check(self):
        results = self._scan("insecure-release.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        missing = self.EXPECTED_IDS - failed
        assert not missing, (
            f"expected every GHA check in EXPECTED_IDS to fail on the "
            f"insecure fixture, but these passed unexpectedly: {missing}"
        )

    def test_secure_release_passes_every_check(self):
        results = self._scan("secure-release.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        missing = self.EXPECTED_IDS - passed
        assert not missing, (
            f"expected every GHA check in EXPECTED_IDS to pass on the "
            f"secure fixture, but these failed: {missing}"
        )


# ────────────────────────────────────────────────────────────────────────────
# GitLab CI
# ────────────────────────────────────────────────────────────────────────────


class TestGitLabFixtures:
    EXPECTED_IDS = (
        {f"GL-{i:03d}" for i in range(1, 43)}
        | {"TAINT-004", "TAINT-008"}
    )

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
    EXPECTED_IDS = {f"BB-{i:03d}" for i in range(1, 33)}

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
    EXPECTED_IDS = {f"ADO-{i:03d}" for i in range(1, 33)}

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
    EXPECTED_IDS = {f"JF-{i:03d}" for i in range(1, 36)}

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
# CircleCI
# ────────────────────────────────────────────────────────────────────────────


class TestCircleCIFixtures:
    EXPECTED_IDS = {f"CC-{i:03d}" for i in range(1, 34)}

    def _scan(self, filename: str):
        ctx = CircleCIContext.from_path(FIXTURES / "circleci" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed configs"
        return _finding_map(CircleCIPipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-config.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every CC check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-config.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every CC check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Google Cloud Build
# ────────────────────────────────────────────────────────────────────────────


class TestCloudBuildFixtures:
    EXPECTED_IDS = {f"GCB-{i:03d}" for i in range(1, 27)}
    # GCB-002 (``serviceAccount`` unset) and GCB-020 (``serviceAccount``
    # points at the default Cloud Build SA email) are mutually-exclusive
    # triggers — a single document satisfies one or the other, never
    # both. The omnibus insecure fixture exercises GCB-002's unset-SA
    # case; GCB-020 is covered by ``tests/test_gcb_rules_020_021.py``.
    INSECURE_EXEMPT: frozenset[str] = frozenset({"GCB-020"})

    def _scan(self, filename: str):
        ctx = CloudBuildContext.from_path(FIXTURES / "cloudbuild" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed documents"
        return _finding_map(CloudBuildPipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-cloudbuild.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        expected_failed = self.EXPECTED_IDS - self.INSECURE_EXEMPT
        assert failed == expected_failed, (
            f"expected every GCB check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {expected_failed - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-cloudbuild.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every GCB check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Buildkite
# ────────────────────────────────────────────────────────────────────────────


class TestBuildkiteFixtures:
    EXPECTED_IDS = {f"BK-{i:03d}" for i in range(1, 16)} | {"TAINT-005"}

    def _scan(self, filename: str):
        ctx = BuildkiteContext.from_path(FIXTURES / "buildkite" / filename)
        assert ctx.pipelines, f"fixture {filename} produced no parsed pipelines"
        return _finding_map(BuildkitePipelineChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-pipeline.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every BK check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-pipeline.yml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every BK check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Dockerfile / Containerfile
# ────────────────────────────────────────────────────────────────────────────


class TestDockerfileFixtures:
    EXPECTED_IDS = {f"DF-{i:03d}" for i in range(1, 32)}

    def _scan(self, filename: str):
        ctx = DockerfileContext.from_path(FIXTURES / "dockerfile" / filename)
        assert ctx.dockerfiles, f"fixture {filename} produced no parsed documents"
        return _finding_map(DockerfileChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-Dockerfile")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every DF check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-Dockerfile")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every DF check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Kubernetes manifests
# ────────────────────────────────────────────────────────────────────────────


class TestKubernetesFixtures:
    EXPECTED_IDS = {f"K8S-{i:03d}" for i in range(1, 45)}

    def _scan(self, filename: str):
        ctx = KubernetesContext.from_path(FIXTURES / "k8s" / filename)
        assert ctx.manifests, f"fixture {filename} produced no parsed manifests"
        return _finding_map(KubernetesManifestChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every K8S check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every K8S check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Tekton
# ────────────────────────────────────────────────────────────────────────────


class TestTektonFixtures:
    EXPECTED_IDS = {f"TKN-{i:03d}" for i in range(1, 17)} | {"TAINT-006"}

    def _scan(self, filename: str):
        ctx = TektonContext.from_path(FIXTURES / "tekton" / filename)
        assert ctx.docs, f"fixture {filename} produced no parsed docs"
        return _finding_map(TektonChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-tekton.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every TKN check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-tekton.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every TKN check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Argo Workflows
# ────────────────────────────────────────────────────────────────────────────


class TestArgoFixtures:
    EXPECTED_IDS = {f"ARGO-{i:03d}" for i in range(1, 18)} | {"TAINT-007"}

    def _scan(self, filename: str):
        ctx = ArgoContext.from_path(FIXTURES / "argo" / filename)
        assert ctx.docs, f"fixture {filename} produced no parsed docs"
        return _finding_map(ArgoChecks(ctx).run())

    def test_insecure_fails_every_check(self):
        results = self._scan("insecure-argo.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        failed = {cid for cid, passed in results.items() if not passed}
        assert failed == self.EXPECTED_IDS, (
            f"expected every ARGO check to fail on the insecure fixture, "
            f"but these passed unexpectedly: {self.EXPECTED_IDS - failed}"
        )

    def test_secure_passes_every_check(self):
        results = self._scan("secure-argo.yaml")
        assert self.EXPECTED_IDS.issubset(results.keys())
        passed = {cid for cid, ok in results.items() if ok}
        assert passed == self.EXPECTED_IDS, (
            f"expected every ARGO check to pass on the secure fixture, "
            f"but these failed: {self.EXPECTED_IDS - passed}"
        )


# ────────────────────────────────────────────────────────────────────────────
# Cross-provider sanity — findings carry control refs from enabled standards
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("provider,fixture,loader,checker,expected", [
    ("github", "github/insecure-release.yml", GitHubContext, WorkflowChecks,
     ({f"GHA-{i:03d}" for i in range(1, 63)} - {"GHA-062"})
     | {"TAINT-001", "TAINT-002", "TAINT-003"}),
    ("gitlab", "gitlab/insecure.gitlab-ci.yml", GitLabContext, GitLabPipelineChecks,
     {f"GL-{i:03d}" for i in range(1, 41)} | {"TAINT-004", "TAINT-008"}),
    ("bitbucket", "bitbucket/insecure-bitbucket-pipelines.yml",
     BitbucketContext, BitbucketPipelineChecks,
     {f"BB-{i:03d}" for i in range(1, 32)}),
    ("azure", "azure/insecure-azure-pipelines.yml",
     AzureContext, AzurePipelineChecks,
     {f"ADO-{i:03d}" for i in range(1, 33)}),
    ("jenkins", "jenkins/Jenkinsfile.insecure", JenkinsContext, JenkinsfileChecks,
     {f"JF-{i:03d}" for i in range(1, 36)}),
    ("circleci", "circleci/insecure-config.yml", CircleCIContext, CircleCIPipelineChecks,
     {f"CC-{i:03d}" for i in range(1, 34)}),
    ("buildkite", "buildkite/insecure-pipeline.yml",
     BuildkiteContext, BuildkitePipelineChecks,
     {f"BK-{i:03d}" for i in range(1, 16)} | {"TAINT-005"}),
    ("tekton", "tekton/insecure-tekton.yaml",
     TektonContext, TektonChecks,
     {f"TKN-{i:03d}" for i in range(1, 17)} | {"TAINT-006"}),
    ("argo", "argo/insecure-argo.yaml",
     ArgoContext, ArgoChecks,
     {f"ARGO-{i:03d}" for i in range(1, 17)} | {"TAINT-007"}),
    ("cloudbuild", "cloudbuild/insecure-cloudbuild.yaml",
     CloudBuildContext, CloudBuildPipelineChecks,
     {f"GCB-{i:03d}" for i in range(1, 27)}),
    ("dockerfile", "dockerfile/insecure-Dockerfile",
     DockerfileContext, DockerfileChecks,
     {f"DF-{i:03d}" for i in range(1, 31)}),
    ("kubernetes", "k8s/insecure.yaml",
     KubernetesContext, KubernetesManifestChecks,
     {f"K8S-{i:03d}" for i in range(1, 44)}),
])
def test_every_insecure_fixture_emits_expected_check_ids(
    provider, fixture, loader, checker, expected
):
    """Each insecure fixture emits at least the expected set of check
    IDs (no missing checks). Extra IDs that fall outside the expected
    set are tolerated for rules whose firing requires sidecar files
    not present in the shared insecure fixture (e.g. GHA-062's
    trust-policy.json walk)."""
    ctx = loader.from_path(FIXTURES / fixture)
    emitted = {f.check_id for f in checker(ctx).run()}
    missing = expected - emitted
    assert not missing, (
        f"[{provider}] expected check IDs missing from output: {missing}"
    )
