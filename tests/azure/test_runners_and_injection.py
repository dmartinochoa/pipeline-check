"""Per-rule tests for Azure DevOps runner / injection / template rules:
ADO-013 (self-hosted agent pool ephemeral marker),
ADO-020 (vulnerability scanning on artifact-producing pipelines),
ADO-025 (cross-repo template not pinned to commit SHA),
ADO-027 (dangerous shell idiom).

Pushes Azure per-rule coverage past the 60% threshold.
"""
from __future__ import annotations

from .conftest import run_check

# ── ADO-013 self-hosted pool ephemeral marker ───────────────────────


class TestADO013SelfHostedEphemeral:
    def test_fails_when_self_hosted_pool_lacks_ephemeral(self):
        cfg = """
        pool:
          name: build-pool
        steps:
          - script: make
        """
        f = run_check(cfg, "ADO-013")
        assert not f.passed

    def test_passes_with_ephemeral_demand(self):
        cfg = """
        pool:
          name: build-pool
          demands:
            - ephemeral -equals true
        steps:
          - script: make
        """
        f = run_check(cfg, "ADO-013")
        assert f.passed

    def test_passes_on_microsoft_hosted_image(self):
        cfg = """
        pool:
          vmImage: ubuntu-latest
        steps:
          - script: make
        """
        f = run_check(cfg, "ADO-013")
        assert f.passed


# ── ADO-020 vulnerability scanning ──────────────────────────────────


class TestADO020VulnScanning:
    def test_fails_when_artifact_built_without_scan(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-020")
        assert not f.passed

    def test_passes_with_trivy_scan(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: trivy image --severity HIGH,CRITICAL registry.example.com/app:v1
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-020")
        assert f.passed


# ── ADO-025 cross-repo template pinning ─────────────────────────────


class TestADO025TemplatePinning:
    def test_fails_when_cross_repo_template_lacks_ref(self):
        # ``template: build.yml@tools`` with no ref on the ``tools``
        # repo resource follows the pipeline's default branch -- a
        # push to the callee repo swaps the template body.
        cfg = """
        resources:
          repositories:
            - repository: tools
              type: git
              name: org/tools
        pool: {vmImage: ubuntu-latest}
        steps:
          - template: build.yml@tools
        """
        f = run_check(cfg, "ADO-025")
        assert not f.passed

    def test_fails_when_cross_repo_template_pinned_to_branch(self):
        cfg = """
        resources:
          repositories:
            - repository: tools
              type: git
              name: org/tools
              ref: refs/heads/main
        pool: {vmImage: ubuntu-latest}
        steps:
          - template: build.yml@tools
        """
        f = run_check(cfg, "ADO-025")
        assert not f.passed

    def test_passes_when_cross_repo_template_pinned_to_commit_sha(self):
        cfg = """
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
        f = run_check(cfg, "ADO-025")
        assert f.passed


# ── ADO-027 dangerous shell idiom ───────────────────────────────────


class TestADO027ShellEval:
    def test_fails_on_eval_of_variable(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: eval "$BUILD_CMD"
        """
        f = run_check(cfg, "ADO-027")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: sh -c "$USER_CMD"
        """
        f = run_check(cfg, "ADO-027")
        assert not f.passed

    def test_passes_when_clean(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: make test
        """
        f = run_check(cfg, "ADO-027")
        assert f.passed
