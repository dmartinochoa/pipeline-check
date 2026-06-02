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
from pipeline_check.core.checks.circleci.rules import cc026_malicious_activity as cc026

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
