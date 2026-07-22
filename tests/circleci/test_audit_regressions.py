"""Regression tests from the rule audit (CircleCI example fix)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks._primitives import tls_bypass
from pipeline_check.core.checks._primitives.go_insecure_env import (
    insecure_settings_in_script,
)
from pipeline_check.core.checks.circleci.rules import cc002_script_injection as cc002
from pipeline_check.core.checks.circleci.rules import cc003_docker_image_pinning as cc003
from pipeline_check.core.checks.circleci.rules import cc008_literal_secrets as cc008
from pipeline_check.core.checks.circleci.rules import cc015_timeout as cc015
from pipeline_check.core.checks.circleci.rules import cc019_ssh_keys as cc019
from pipeline_check.core.checks.circleci.rules import cc024_slsa_provenance as cc024
from pipeline_check.core.checks.circleci.rules import cc026_malicious_activity as cc026
from pipeline_check.core.checks.circleci.rules import cc031_oidc_trust as cc031

from .conftest import run_check


class TestCC008LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # The Vulnerable fragment must fire; it previously used vendor
        # example tokens (AKIAIOSFODNN7EXAMPLE) that find_secret_values
        # suppresses, so the documented example passed.
        vuln, safe = cc008.RULE.exploit_example.split("\n\n", 1)
        assert cc008.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc008.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC003DockerImagePinning:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used @sha256:abc123... which is only
        # 6 hex chars; DIGEST_RE requires exactly 64, so the safe config
        # was flagged. Fixed by using a full 64-hex digest.
        vuln, safe = cc003.RULE.exploit_example.split("\n\n", 1)
        assert cc003.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc003.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC002ScriptInjection:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously assigned $CIRCLE_BRANCH to a local
        # shell variable; UNTRUSTED_ENV_RE matches the variable name
        # regardless of quoting, so the safe config was flagged.
        # Fixed by using a CircleCI pipeline parameter instead, which
        # never contains the untrusted variable name in a run step.
        vuln, safe = cc002.RULE.exploit_example.split("\n\n", 1)
        assert cc002.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc002.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC026MaliciousActivity:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment previously used a 12-char base64 blob
        # (Z2g6Li4uIA==) which is below the 30-char minimum required
        # by _B64_BLOB; the line only fired via the webhook.site
        # exfil-channel pattern, not the intended obfuscated-exec
        # pattern. Fixed with a 52-char blob that fires both detectors.
        vuln, safe = cc026.RULE.exploit_example.split("\n\n", 1)
        result = cc026.check(".circleci/config.yml", yaml.safe_load(vuln))
        assert result.passed is False
        assert "obfuscated-exec" in result.description
        assert cc026.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


# ── CC-004 word-boundary fix ──────────────────────────────────────────────


class TestCC004ContextRestrictions:
    """Non-secret names containing TOKEN/SECRET as substrings must not fire."""

    def _cfg(self, env_var_name: str) -> str:
        return f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:{'0' * 64}
            environment:
              {env_var_name}: some_value
            steps: [checkout]
        """

    # --- FP cases: benign names that previously triggered ---

    def test_passes_tokenizer_version(self):
        # TOKENIZER_VERSION contains TOKEN but is not a secret variable.
        f = run_check(self._cfg("TOKENIZER_VERSION"), "CC-004")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_passes_secret_scanning_enabled(self):
        # SECRET_SCANNING_ENABLED contains SECRET but is not a credential.
        f = run_check(self._cfg("SECRET_SCANNING_ENABLED"), "CC-004")
        assert f.passed, f"Expected pass, got: {f.description}"

    # --- TP cases: real secret names that must still fire ---

    def test_fires_on_npm_token(self):
        f = run_check(self._cfg("NPM_TOKEN"), "CC-004")
        assert not f.passed

    def test_fires_on_database_password(self):
        f = run_check(self._cfg("DATABASE_PASSWORD"), "CC-004")
        assert not f.passed

    def test_fires_on_gh_token(self):
        f = run_check(self._cfg("GH_TOKEN"), "CC-004")
        assert not f.passed

    def test_fires_on_api_key(self):
        f = run_check(self._cfg("API_KEY"), "CC-004")
        assert not f.passed

    def test_fires_on_my_secret(self):
        f = run_check(self._cfg("MY_SECRET"), "CC-004")
        assert not f.passed

    def test_fires_on_deploy_token(self):
        f = run_check(self._cfg("DEPLOY_TOKEN"), "CC-004")
        assert not f.passed


# ── CC-033 / go_insecure_env shell-comment stripping ─────────────────────


class TestCC033ShellCommentStrip:
    """Commented-out insecure exports must not fire; live exports must."""

    def test_passes_commented_gosumdb_export(self):
        # A disabled export in a comment must not trigger CC-033.
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run: |
                  # do not export GOSUMDB=off
                  go build ./...
        """, "CC-033")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_passes_commented_goflags_export(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run: |
                  # export GOFLAGS=-insecure
                  go build ./...
        """, "CC-033")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_fires_on_live_gosumdb_export(self):
        # A real (un-commented) export must still fire.
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run: |
                  export GOSUMDB=off
                  go build ./...
        """, "CC-033")
        assert not f.passed

    def test_fires_on_live_goflags_export(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run: |
                  export GOFLAGS=-insecure
                  go build ./...
        """, "CC-033")
        assert not f.passed


class TestGoInsecureEnvCommentStrip:
    """Unit tests for the shared primitive directly."""

    def test_commented_gosumdb_off_not_flagged(self):
        assert insecure_settings_in_script("# export GOSUMDB=off\ngo build") == []

    def test_commented_goflags_not_flagged(self):
        assert insecure_settings_in_script("# export GOFLAGS=-insecure") == []

    def test_live_gosumdb_off_flagged(self):
        assert insecure_settings_in_script("export GOSUMDB=off") != []

    def test_live_goflags_flagged(self):
        assert insecure_settings_in_script("export GOFLAGS=-insecure") != []

    def test_comment_after_live_export_still_fires(self):
        # Comment on a subsequent line should not suppress the live export.
        script = "export GOSUMDB=off  # this is bad\ngo build"
        assert insecure_settings_in_script(script) != []


# ── CC-023 / tls_bypass curl -K FP ───────────────────────────────────────


class TestCC023TlsBypassCurlCase:
    """`curl -K` (--config) must not trigger; `curl -k` / `--insecure` must."""

    def _cfg(self, run_cmd: str) -> str:
        return f"""
        version: 2.1
        jobs:
          fetch:
            docker:
              - image: cimg/base@sha256:{'0' * 64}
            steps:
              - run: {run_cmd!r}
        """

    def test_passes_curl_uppercase_K(self):
        # -K is curl's --config flag, not a TLS bypass.
        f = run_check(self._cfg("curl -K /tmp/curl.cfg https://example.com/file"), "CC-023")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_fires_on_curl_lowercase_k(self):
        f = run_check(self._cfg("curl -k https://example.com/file"), "CC-023")
        assert not f.passed

    def test_fires_on_curl_insecure(self):
        f = run_check(self._cfg("curl --insecure https://example.com/file"), "CC-023")
        assert not f.passed


class TestTlsBypassCurlCasePrimitive:
    """Unit tests for tls_bypass.scan case-sensitivity directly."""

    def test_curl_uppercase_K_not_matched(self):
        hits = tls_bypass.scan("curl -K /tmp/curl.cfg https://example.com")
        kinds = [h.kind for h in hits]
        assert "curl-insecure" not in kinds, f"Unexpected hit: {hits}"

    def test_curl_lowercase_k_matched(self):
        hits = tls_bypass.scan("curl -k https://example.com")
        assert any(h.kind == "curl-insecure" for h in hits)

    def test_curl_insecure_flag_matched(self):
        hits = tls_bypass.scan("curl --insecure https://example.com")
        assert any(h.kind == "curl-insecure" for h in hits)

    def test_curl_INSECURE_flag_matched(self):
        # --insecure is case-insensitive.
        hits = tls_bypass.scan("curl --INSECURE https://example.com")
        assert any(h.kind == "curl-insecure" for h in hits)


# ── CC-025 .Revision FP ───────────────────────────────────────────────────


class TestCC025CacheKeyRevision:
    """`.Revision` (git commit SHA) in a cache key must not trigger CC-025."""

    def _cfg_revision(self) -> str:
        return """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - restore_cache:
                  keys:
                    - deps-{{ .Revision }}
              - run: npm ci
              - save_cache:
                  key: deps-{{ .Revision }}
                  paths: [node_modules]
        """

    def _cfg_branch(self) -> str:
        return """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - save_cache:
                  key: deps-{{ .Branch }}
                  paths: [node_modules]
        """

    def test_passes_revision_keyed_cache(self):
        # .Revision is a content-addressed SHA; not attacker-controllable.
        f = run_check(self._cfg_revision(), "CC-025")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_fires_on_branch_keyed_cache(self):
        # .Branch is attacker-controllable via a PR branch name.
        f = run_check(self._cfg_branch(), "CC-025")
        assert not f.passed


# ── CC-029 legacy dash-format machine image ───────────────────────────────


class TestCC029MachineImageLegacyTag:
    """Legacy `:YYYYMM-NN` image tags are immutable and must not fire."""

    def _cfg(self, image: str) -> str:
        return f"""
        version: 2.1
        jobs:
          build:
            machine:
              image: {image}
            steps: [checkout]
        """

    def test_passes_legacy_dash_format(self):
        # ubuntu-2004:202010-01 is a pinned legacy release tag.
        f = run_check(self._cfg("ubuntu-2004:202010-01"), "CC-029")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_passes_newer_legacy_dash_format(self):
        f = run_check(self._cfg("ubuntu-2004:202201-02"), "CC-029")
        assert f.passed, f"Expected pass, got: {f.description}"

    def test_fires_on_rolling_current(self):
        f = run_check(self._cfg("ubuntu-2004:current"), "CC-029")
        assert not f.passed

    def test_fires_on_rolling_edge(self):
        f = run_check(self._cfg("ubuntu-2204:edge"), "CC-029")
        assert not f.passed

    def test_passes_new_dotted_format(self):
        # Confirm the existing dotted format still passes.
        f = run_check(self._cfg("ubuntu-2204:2024.05.1"), "CC-029")
        assert f.passed


def _load(text: str) -> dict:
    return yaml.safe_load(text)


# ── CC-015 blob_lower fallback false-negative ────────────────────────


class TestCC015BlobFallbackFN:
    """CC-015: blob_lower() fallback matched the token as a string VALUE
    (e.g. a step name), never as a YAML key. Drop the fallback so a
    config that only MENTIONS the word in a name: field still fails.
    """

    def test_fires_when_token_only_in_step_name(self):
        # 'no_output_timeout' appears only as a step name value, not as
        # a run-step key. Previously the blob fallback swallowed this and
        # returned passed=True (false negative).
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          name: "remind team to set no_output_timeout"
          command: ./build.sh
""")
        assert cc015.check("cfg.yml", doc).passed is False

    def test_passes_with_real_run_step_timeout(self):
        # A genuine no_output_timeout: key on a run step must still pass.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          name: long build
          no_output_timeout: 20m
          command: ./build.sh
""")
        assert cc015.check("cfg.yml", doc).passed is True

    def test_passes_when_no_author_run_steps(self):
        # 2026-07 audit: a config with no author ``run:`` step (only a
        # checkout / orb steps) has nothing to set ``no_output_timeout``
        # on, so it is not applicable and must pass rather than fire.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - checkout
""")
        assert cc015.check("cfg.yml", doc).passed is True


# ── CC-019 commands block and when:/unless: false-negatives ─────────


class TestCC019CommandsAndConditionalFN:
    """CC-019: bare add_ssh_keys inside reusable commands: or inside a
    when:/unless: conditional step group was previously missed.
    """

    def test_fires_bare_add_ssh_keys_in_commands_block(self):
        # A top-level commands: entry with a bare add_ssh_keys step must fire.
        doc = _load("""
version: 2.1
commands:
  setup_keys:
    steps:
      - add_ssh_keys
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - setup_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_fires_bare_add_ssh_keys_inside_when_group(self):
        # A bare add_ssh_keys nested under a when: conditional group must fire.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - when:
          condition: << parameters.deploy >>
          steps:
            - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_fires_bare_add_ssh_keys_inside_unless_group(self):
        # A bare add_ssh_keys nested under an unless: conditional group must fire.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - unless:
          condition: << parameters.skip_keys >>
          steps:
            - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False

    def test_passes_with_fingerprints_in_commands_block(self):
        # A commands: entry that uses add_ssh_keys WITH fingerprints is safe.
        doc = _load("""
version: 2.1
commands:
  setup_keys:
    steps:
      - add_ssh_keys:
          fingerprints:
            - "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - setup_keys
""")
        assert cc019.check("cfg.yml", doc).passed is True

    def test_existing_bare_job_step_still_fires(self):
        # Regression: the original top-level job step path must still work.
        doc = _load("""
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - add_ssh_keys
""")
        assert cc019.check("cfg.yml", doc).passed is False


# ── CC-031 underscore parameter forms false-negative ─────────────────


class TestCC031UnderscoreParamsFN:
    """CC-031: only hyphenated param names (role-arn) were in
    _OIDC_ROLE_PARAMS; the underscore forms (role_arn, oidc_role_arn)
    were silently ignored.
    """

    def test_fires_on_role_arn_underscore_no_gate(self):
        # role_arn (underscore) without branch filter or approval must fire.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role_arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False

    def test_fires_on_oidc_role_arn_underscore_no_gate(self):
        # oidc_role_arn (underscore) without a gate must fire.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          oidc_role_arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False

    def test_passes_on_role_arn_underscore_with_branch_filter(self):
        # role_arn with a branch filter is safe (same as hyphenated form).
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role_arn: arn:aws:iam::123456789012:role/prod-deploy
          filters:
            branches:
              only: main
""")
        assert cc031.check("cfg.yml", doc).passed is True

    def test_hyphenated_form_still_fires(self):
        # Existing hyphenated form (role-arn) must still fire without a gate.
        doc = _load("""
version: 2.1
orbs:
  aws: circleci/aws-cli@5.1.0
jobs:
  deploy:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: aws s3 ls
workflows:
  main:
    jobs:
      - deploy:
          role-arn: arn:aws:iam::123456789012:role/prod-deploy
""")
        assert cc031.check("cfg.yml", doc).passed is False


# ── CC-024 batch-5 FN: circleci/attestation orb not in PROVENANCE_TOKENS ─


class TestCC024CircleCIAttestationOrb:
    """CC-024: the recommendation names the ``circleci/attestation`` orb
    as the canonical CircleCI SLSA provenance mechanism, but neither
    ``circleci/attestation`` nor ``attestation/attest`` was in
    PROVENANCE_TOKENS, so a config using that orb was incorrectly flagged
    as lacking provenance."""

    def test_circleci_attestation_orb_passes_cc024(self):
        # A config that uses the circleci/attestation orb must pass CC024.
        doc = _load("""
version: 2.1
orbs:
  attestation: circleci/attestation@0.0.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: |
            docker build -t registry.example.com/app:v1 .
            docker push registry.example.com/app:v1
      - attestation/attest:
          image-ref: registry.example.com/app:v1
          digest: sha256:abc123
workflows:
  main:
    jobs:
      - build
""")
        assert cc024.check(".circleci/config.yml", doc).passed is True, (
            "CC-024 must pass when the circleci/attestation orb is used"
        )

    def test_no_provenance_artifact_pipeline_fires_cc024(self):
        # A config that publishes but has no provenance step must still fire.
        doc = _load("""
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: |
            docker build -t registry.example.com/app:v1 .
            docker push registry.example.com/app:v1
workflows:
  main:
    jobs:
      - build
""")
        assert cc024.check(".circleci/config.yml", doc).passed is False, (
            "CC-024 must fire when an artifact config has no provenance step"
        )

    def test_no_artifact_config_skips_cc024(self):
        # A config with no artifact-producing step must skip CC-024 (no FP).
        doc = _load("""
version: 2.1
jobs:
  test:
    docker:
      - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
    steps:
      - run:
          no_output_timeout: 10m
          command: pytest tests/
workflows:
  main:
    jobs:
      - test
""")
        assert cc024.check(".circleci/config.yml", doc).passed is True, (
            "CC-024 must pass (no artifact) on a test-only config"
        )


class TestAudit202607LowCircleCI:
    """2026-07 audit LOW findings on the CircleCI rules."""

    @staticmethod
    def _run(text, check_id):
        from tests.circleci.conftest import run_check
        return run_check(text, check_id)

    def test_cc009_non_list_requires_does_not_crash(self):
        cfg = (
            "version: 2.1\n"
            "jobs:\n"
            "  deploy: { docker: [{image: cimg/base}], steps: [{run: make}] }\n"
            "workflows:\n"
            "  release:\n"
            "    jobs:\n"
            "      - deploy: { requires: {hold: yes} }\n"
        )
        # Must not raise TypeError on the unhashable dict entry.
        f = self._run(cfg, "CC-009")
        assert f is not None

    def test_cc005_executor_env_aws_keys_fire(self):
        cfg = (
            "version: 2.1\n"
            "executors:\n"
            "  awsx:\n"
            "    docker: [{image: cimg/base}]\n"
            "    environment: { AWS_ACCESS_KEY_ID: AKIA, AWS_SECRET_ACCESS_KEY: x }\n"
            "jobs:\n"
            "  deploy: { executor: awsx, steps: [{run: aws s3 ls}] }\n"
            "workflows: { w: { jobs: [deploy] } }\n"
        )
        assert self._run(cfg, "CC-005").passed is False

    def test_cc004_executor_env_secret_fires(self):
        cfg = (
            "version: 2.1\n"
            "executors:\n"
            "  e1:\n"
            "    docker: [{image: cimg/base}]\n"
            "    environment: { DB_PASSWORD: hunter2 }\n"
            "jobs:\n"
            "  build: { executor: e1, steps: [{run: make}] }\n"
            "workflows: { w: { jobs: [build] } }\n"
        )
        assert self._run(cfg, "CC-004").passed is False

    def test_cc010_namespaced_runner_fires_managed_class_does_not(self):
        base = (
            "version: 2.1\n"
            "jobs:\n"
            "  build: {{ resource_class: {rc}, steps: [{{run: make}}] }}\n"
            "workflows: {{ w: {{ jobs: [build] }} }}\n"
        )
        assert self._run(base.format(rc="my-org/linux-arm"), "CC-010").passed is False
        assert self._run(base.format(rc="my-org/ephemeral-arm"), "CC-010").passed is True
        assert self._run(base.format(rc="large"), "CC-010").passed is True

    def test_cc011_only_fires_when_tests_run(self):
        no_tests = (
            "version: 2.1\n"
            "jobs:\n"
            "  build: { docker: [{image: cimg/base}], steps: [{run: make}] }\n"
            "workflows: { w: { jobs: [build] } }\n"
        )
        assert self._run(no_tests, "CC-011").passed is True
        with_tests = (
            "version: 2.1\n"
            "jobs:\n"
            "  test: { docker: [{image: cimg/base}], steps: [{run: pytest}] }\n"
            "workflows: { w: { jobs: [test] } }\n"
        )
        assert self._run(with_tests, "CC-011").passed is False


class TestAudit202607LowCircleCIC2C3:
    """2026-07 audit LOW findings (circleci_c2/c3 chunks)."""

    @staticmethod
    def _run(text, cid):
        from tests.circleci.conftest import run_check
        return run_check(text, cid)

    def test_cc021_go_install_local_path_exempt(self):
        local = ("version: 2.1\njobs: {b: {docker: [{image: x}], "
                 "steps: [{run: go install ./cmd/tool}]}}\n"
                 "workflows: {w: {jobs: [b]}}\n")
        assert self._run(local, "CC-021").passed is True
        remote = ("version: 2.1\njobs: {b: {docker: [{image: x}], "
                  "steps: [{run: go install github.com/x/tool}]}}\n"
                  "workflows: {w: {jobs: [b]}}\n")
        assert self._run(remote, "CC-021").passed is False

    def test_cc037_hyphenated_filename_not_an_agent(self):
        fn = ("version: 2.1\njobs: {b: {docker: [{image: x}], steps: "
              "[{run: python run-gemini-benchmark.py --branch $CIRCLE_BRANCH}]}}\n"
              "workflows: {w: {jobs: [b]}}\n")
        assert self._run(fn, "CC-037").passed is True
        real = ("version: 2.1\njobs: {b: {docker: [{image: x}], steps: "
                "[{run: 'gemini -p \"$CIRCLE_BRANCH\"'}]}}\n"
                "workflows: {w: {jobs: [b]}}\n")
        assert self._run(real, "CC-037").passed is False

    def test_cc031_approval_job_not_flagged(self):
        cfg = ("version: 2.1\nworkflows: {w: {jobs: [{gate: "
               "{type: approval, role-arn: 'arn:aws:iam::1:role/x'}}]}}\n")
        assert self._run(cfg, "CC-031").passed is True
