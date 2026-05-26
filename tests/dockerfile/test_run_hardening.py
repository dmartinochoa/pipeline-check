"""Per-rule tests for Dockerfile RUN-step hardening rules:
DF-003 (ADD URL without checksum), DF-004 (curl-pipe in RUN),
DF-005 (RUN shell-eval idiom), DF-008 (RUN docker --privileged),
DF-012 (sudo in RUN).

These five rules cover what happens during the build itself: how
remote content is fetched into the image, what shell idioms run,
and whether the build escalates privilege.
"""
from __future__ import annotations

from .conftest import run_check

_FROM = "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"


# ── DF-003 ADD URL without checksum ─────────────────────────────────


class TestDF003AddUrlUnverified:
    def test_fails_on_add_url_without_checksum(self):
        text = _FROM + "ADD https://example.com/installer.tar.gz /opt/\n"
        f = run_check(text, "DF-003")
        assert not f.passed

    def test_passes_on_add_url_with_checksum(self):
        text = (
            _FROM
            + "ADD --checksum=sha256:0000000000000000000000000000000000000000000000000000000000000002 \\\n"
            + "    https://example.com/installer.tar.gz /opt/\n"
        )
        f = run_check(text, "DF-003")
        assert f.passed

    def test_passes_on_add_url_with_uppercase_checksum(self):
        text = (
            _FROM
            + "ADD --checksum=SHA256:AABBCCDD00112233445566778899AABBCCDD00112233445566778899AABBCCDD \\\n"
            + "    https://example.com/installer.tar.gz /opt/\n"
        )
        f = run_check(text, "DF-003")
        assert f.passed


# ── DF-004 curl-pipe in RUN ─────────────────────────────────────────


class TestDF004RunCurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        text = _FROM + "RUN curl -fsSL https://example.com/install.sh | bash\n"
        f = run_check(text, "DF-004")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        text = _FROM + "RUN wget -O - https://example.com/install.sh | sh\n"
        f = run_check(text, "DF-004")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        text = (
            _FROM
            + "RUN curl -fsSL https://example.com/install.sh -o install.sh && "
            + "echo '0000000000000000000000000000000000000000000000000000000000000003  install.sh' "
            + "| sha256sum -c && bash install.sh\n"
        )
        f = run_check(text, "DF-004")
        assert f.passed


# ── DF-005 RUN shell-eval idiom ─────────────────────────────────────


class TestDF005RunShellEval:
    def test_fails_on_eval_of_variable(self):
        text = _FROM + 'RUN eval "$BUILD_CMD"\n'
        f = run_check(text, "DF-005")
        assert not f.passed

    def test_passes_when_clean(self):
        text = _FROM + "RUN make test\n"
        f = run_check(text, "DF-005")
        assert f.passed


# ── DF-008 RUN docker --privileged ──────────────────────────────────


class TestDF008RunPrivileged:
    def test_fails_on_docker_privileged_in_run(self):
        text = _FROM + "RUN docker run --privileged builder make all\n"
        f = run_check(text, "DF-008")
        assert not f.passed

    def test_passes_when_no_privileged_flag(self):
        text = _FROM + "RUN docker run --rm builder make all\n"
        f = run_check(text, "DF-008")
        assert f.passed


# ── DF-012 sudo in RUN ──────────────────────────────────────────────


class TestDF012RunSudo:
    def test_fails_on_sudo_invocation(self):
        text = _FROM + "RUN sudo apt-get install -y curl\n"
        f = run_check(text, "DF-012")
        assert not f.passed

    def test_passes_without_sudo(self):
        # ``apt-get`` without sudo runs as the current Dockerfile
        # user (root by default during build), so no sudo is needed.
        text = _FROM + "RUN apt-get install -y --no-install-recommends curl=7.88.1-*\n"
        f = run_check(text, "DF-012")
        assert f.passed
