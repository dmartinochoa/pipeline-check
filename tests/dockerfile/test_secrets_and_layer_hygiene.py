"""Per-rule tests for the remaining Dockerfile rules:
DF-006 (ENV/ARG carries credential-shaped literal),
DF-007 (no HEALTHCHECK directive),
DF-009 (ADD where COPY would suffice),
DF-010 (apt-get dist-upgrade pulls unknown package versions),
DF-011 (package install without same-layer cache cleanup).

With these five tests, the Dockerfile provider has full per-rule
coverage. DF-006 covers the secrets surface; DF-007 the runtime-
health signal; DF-009/010/011 cover layer hygiene (image-content
correctness rather than active vulnerabilities).
"""
from __future__ import annotations

from .conftest import run_check

_FROM = "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"


# ── DF-006 secret in ENV / ARG ──────────────────────────────────────


class TestDF006SecretInEnv:
    def test_fails_on_aws_key_in_env(self):
        text = _FROM + "ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        f = run_check(text, "DF-006")
        assert not f.passed

    def test_fails_on_credential_named_arg_with_literal(self):
        text = _FROM + "ARG DATABASE_PASSWORD=hunter2\n"
        f = run_check(text, "DF-006")
        assert not f.passed

    def test_passes_with_no_secret_in_env(self):
        text = _FROM + "ENV PYTHONUNBUFFERED=1\n"
        f = run_check(text, "DF-006")
        assert f.passed

    def test_passes_when_value_is_indirection(self):
        # ``ARG SECRET`` (no default) and ``ENV X=$VAR`` defer the value
        # to build- or runtime; the literal isn't in the layer history.
        text = _FROM + "ARG DATABASE_PASSWORD\nENV API_KEY=$BUILD_KEY\n"
        f = run_check(text, "DF-006")
        assert f.passed


# ── DF-007 HEALTHCHECK directive ────────────────────────────────────


class TestDF007NoHealthcheck:
    def test_fails_when_no_healthcheck_directive(self):
        text = _FROM + 'CMD ["python", "app.py"]\n'
        f = run_check(text, "DF-007")
        assert not f.passed

    def test_passes_with_healthcheck_directive(self):
        text = (
            _FROM
            + "HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\\n"
            + "    CMD curl -fsS http://localhost:8080/healthz || exit 1\n"
            + 'CMD ["python", "app.py"]\n'
        )
        f = run_check(text, "DF-007")
        assert f.passed


# ── DF-009 ADD where COPY would suffice ─────────────────────────────


class TestDF009AddLocalPath:
    def test_fails_when_add_used_for_local_file(self):
        text = _FROM + "ADD ./config.json /opt/config.json\n"
        f = run_check(text, "DF-009")
        assert not f.passed

    def test_passes_when_copy_used_for_local_file(self):
        text = _FROM + "COPY ./config.json /opt/config.json\n"
        f = run_check(text, "DF-009")
        assert f.passed

    def test_passes_when_add_pulls_url(self):
        # ADD with a URL is a deliberate fetch (covered separately by
        # DF-003); DF-009 only fires on local-path ADDs.
        text = _FROM + "ADD https://example.com/installer /opt/\n"
        f = run_check(text, "DF-009")
        assert f.passed


# ── DF-010 apt-get dist-upgrade ─────────────────────────────────────


class TestDF010AptDistUpgrade:
    def test_fails_on_apt_get_dist_upgrade(self):
        text = _FROM + "RUN apt-get update && apt-get dist-upgrade -y\n"
        f = run_check(text, "DF-010")
        assert not f.passed

    def test_passes_on_pinned_apt_install(self):
        text = (
            _FROM
            + "RUN apt-get update && "
            + "apt-get install -y --no-install-recommends curl=7.88.1-* && "
            + "rm -rf /var/lib/apt/lists/*\n"
        )
        f = run_check(text, "DF-010")
        assert f.passed


# ── DF-011 package install without same-layer cleanup ──────────────


class TestDF011PackageCache:
    def test_fails_when_install_lacks_cache_cleanup_in_same_layer(self):
        text = _FROM + "RUN apt-get update && apt-get install -y curl\n"
        f = run_check(text, "DF-011")
        assert not f.passed

    def test_passes_with_apt_cache_cleanup(self):
        text = (
            _FROM
            + "RUN apt-get update && apt-get install -y --no-install-recommends "
            + "curl=7.88.1-* && rm -rf /var/lib/apt/lists/*\n"
        )
        f = run_check(text, "DF-011")
        assert f.passed

    def test_passes_with_apk_no_cache(self):
        text = _FROM + "RUN apk add --no-cache curl\n"
        f = run_check(text, "DF-011")
        assert f.passed
