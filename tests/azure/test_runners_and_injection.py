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


# ── ADO-030 pool injection ──────────────────────────────────────────


class TestADO030PoolInjection:
    def test_fails_on_template_parameter_at_top_level(self):
        # Caller-controlled template parameter routes the WHOLE
        # pipeline onto whatever pool the caller picks — most direct
        # parity with the GHA-036 reusable-workflow attack.
        cfg = """
        parameters:
          - name: poolName
            type: string
            default: ubuntu-latest
        pool: ${{ parameters.poolName }}
        jobs:
          - job: build
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert not f.passed
        assert "<top>" in f.description

    def test_fails_on_template_parameter_in_dict_form_name(self):
        cfg = """
        parameters:
          - name: poolName
            type: string
        jobs:
          - job: build
            pool:
              name: ${{ parameters.poolName }}
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert not f.passed

    def test_fails_on_runtime_macro_in_demands(self):
        # ``demands:`` is a label-style targeting filter. Letting a
        # PR-controlled macro into the demand picks which agent the
        # job lands on (the agent that satisfies the crafted demand).
        cfg = """
        jobs:
          - job: build
            pool:
              name: prod-pool
              demands:
                - $(Build.SourceBranchName) -equals release
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert not f.passed

    def test_fails_on_pull_request_source_branch(self):
        cfg = """
        jobs:
          - job: build
            pool: $(System.PullRequest.SourceBranch)
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert not f.passed

    def test_fails_when_demands_is_string_form(self):
        # ``demands:`` accepts a single string scalar in addition to
        # the canonical list form. Same threat surface.
        cfg = """
        jobs:
          - job: build
            pool:
              name: prod-pool
              demands: "$(Build.SourceBranchName)"
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert not f.passed

    def test_passes_on_static_pool_string(self):
        cfg = """
        pool: ubuntu-latest
        jobs:
          - job: build
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert f.passed

    def test_passes_on_vmimage(self):
        # Microsoft-hosted vmImage is not a privileged-runner
        # targeting surface — the rule deliberately skips it.
        cfg = """
        jobs:
          - job: build
            pool:
              vmImage: ubuntu-latest
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert f.passed

    def test_passes_on_static_demands(self):
        cfg = """
        jobs:
          - job: build
            pool:
              name: prod-pool
              demands:
                - ephemeral -equals true
                - agent.os -equals Linux
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert f.passed

    def test_passes_on_pipeline_variable(self):
        # ``$(POOL_NAME)`` defined by the author in ``variables:`` is
        # not in the curated untrusted-macro catalog. Static custom
        # variables remain author-controlled.
        cfg = """
        variables:
          POOL_NAME: prod-pool
        jobs:
          - job: build
            pool: $(POOL_NAME)
            steps:
              - script: make
        """
        f = run_check(cfg, "ADO-030")
        assert f.passed
