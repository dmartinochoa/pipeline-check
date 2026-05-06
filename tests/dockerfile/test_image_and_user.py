"""Per-rule tests for Dockerfile image/user/layer rules:
DF-001 (FROM not digest-pinned), DF-002 (no USER directive),
DF-013 (EXPOSE remote-access port), DF-014 (WORKDIR system path).

These four rules cover the image-identity and runtime-identity
basics: which image runs, which user it runs as, what ports are
documented as exposed, and whether the working directory is a
sensitive system path.
"""
from __future__ import annotations

from .conftest import run_check

# ── DF-001 FROM digest pinning ──────────────────────────────────────


class TestDF001ImagePinning:
    def test_fails_on_floating_tag(self):
        f = run_check("FROM python:3.12-slim\nCMD [\"x\"]\n", "DF-001")
        assert not f.passed

    def test_fails_when_no_tag(self):
        f = run_check("FROM python\nCMD [\"x\"]\n", "DF-001")
        assert not f.passed

    def test_passes_with_digest_pin(self):
        f = run_check(
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\nCMD [\"x\"]\n",
            "DF-001",
        )
        assert f.passed


# ── DF-002 USER directive ───────────────────────────────────────────


class TestDF002UserDirective:
    def test_fails_when_no_user_directive(self):
        f = run_check(
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\nCMD [\"x\"]\n",
            "DF-002",
        )
        assert not f.passed

    def test_passes_with_non_root_user(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "RUN useradd --uid 1001 --create-home appuser\n"
            "USER appuser\n"
            "CMD [\"x\"]\n"
        )
        f = run_check(text, "DF-002")
        assert f.passed


# ── DF-013 EXPOSE remote-access port ────────────────────────────────


class TestDF013ExposeSSH:
    def test_fails_on_expose_22(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "EXPOSE 22\n"
        )
        f = run_check(text, "DF-013")
        assert not f.passed

    def test_fails_on_expose_3389_rdp(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "EXPOSE 3389\n"
        )
        f = run_check(text, "DF-013")
        assert not f.passed

    def test_passes_on_expose_application_port(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "EXPOSE 8080\n"
        )
        f = run_check(text, "DF-013")
        assert f.passed


# ── DF-014 WORKDIR system path ──────────────────────────────────────


class TestDF014WorkdirSystemPath:
    def test_fails_on_workdir_etc(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "WORKDIR /etc/app\n"
        )
        f = run_check(text, "DF-014")
        assert not f.passed

    def test_passes_on_workdir_app_dir(self):
        text = (
            "FROM python@sha256:0000000000000000000000000000000000000000000000000000000000000001\n"
            "WORKDIR /app\n"
        )
        f = run_check(text, "DF-014")
        assert f.passed
