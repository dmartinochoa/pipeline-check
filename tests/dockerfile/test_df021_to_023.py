"""Per-rule tests for Dockerfile DF-021..023.

DF-021 (pip install TLS bypass / HTTP index),
DF-022 (RUN npm install instead of npm ci),
DF-023 (ENV sets a dynamic-loader hijack variable).
"""
from __future__ import annotations

from .conftest import run_check

# ── DF-021 pip install TLS bypass ────────────────────────────────────


class TestDF021:
    def test_fails_with_trusted_host(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
USER 1001
HEALTHCHECK CMD true
LABEL org.opencontainers.image.source="https://example.com/x"
LABEL org.opencontainers.image.revision="0000000000000000000000000000000000000000"
RUN pip install --trusted-host pypi.example.com requests
"""
        f = run_check(text, "DF-021")
        assert not f.passed
        assert "trusted-host" in f.description

    def test_fails_with_http_index_url(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN pip install -i http://pypi.example.com/simple requests
"""
        f = run_check(text, "DF-021")
        assert not f.passed
        assert "http://" in f.description

    def test_fails_with_extra_index_url_http(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN pip install --extra-index-url http://internal.example.com/simple requests
"""
        f = run_check(text, "DF-021")
        assert not f.passed

    def test_fires_on_python_m_pip(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN python3 -m pip install --trusted-host pypi.example.com requests
"""
        f = run_check(text, "DF-021")
        assert not f.passed

    def test_passes_with_https_index(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN pip install -i https://pypi.example.com/simple requests
"""
        f = run_check(text, "DF-021")
        assert f.passed

    def test_passes_without_pip_install(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo hello
"""
        f = run_check(text, "DF-021")
        assert f.passed


# ── DF-022 npm install vs npm ci ─────────────────────────────────────


class TestDF022:
    def test_fails_with_npm_install(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm install
"""
        f = run_check(text, "DF-022")
        assert not f.passed

    def test_fails_with_npm_i_alias(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm i
"""
        f = run_check(text, "DF-022")
        assert not f.passed

    def test_fails_with_production_flag(self):
        # ``--production`` still mutates the lockfile.
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm install --production
"""
        f = run_check(text, "DF-022")
        assert not f.passed

    def test_passes_with_npm_ci(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm ci
"""
        f = run_check(text, "DF-022")
        assert f.passed

    def test_passes_with_global_install(self):
        # Global CLI installs (``npm i -g <pkg>``) are intentionally not
        # flagged — they don't pretend to be reproducible.
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm i -g typescript
"""
        f = run_check(text, "DF-022")
        assert f.passed

    def test_passes_without_npm(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo hello
"""
        f = run_check(text, "DF-022")
        assert f.passed


# ── DF-023 ENV LD_PRELOAD / LD_LIBRARY_PATH ──────────────────────────


class TestDF023:
    def test_fails_on_ld_preload(self):
        text = """\
FROM debian:12@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV LD_PRELOAD=/opt/hook/libhook.so
"""
        f = run_check(text, "DF-023")
        assert not f.passed
        assert "LD_PRELOAD" in f.description

    def test_fails_on_ld_library_path(self):
        text = """\
FROM debian:12@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV LD_LIBRARY_PATH=/tmp/lib
"""
        f = run_check(text, "DF-023")
        assert not f.passed

    def test_fails_on_ld_audit(self):
        text = """\
FROM debian:12@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV LD_AUDIT=/opt/audit/libaudit.so
"""
        f = run_check(text, "DF-023")
        assert not f.passed

    def test_passes_when_value_is_empty(self):
        # Empty assignment clears an inherited value; not a hijack.
        text = """\
FROM debian:12@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV LD_PRELOAD=
"""
        f = run_check(text, "DF-023")
        assert f.passed

    def test_passes_when_no_loader_env(self):
        text = """\
FROM debian:12@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV APP_HOME=/srv/app
"""
        f = run_check(text, "DF-023")
        assert f.passed
