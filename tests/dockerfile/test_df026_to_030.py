"""Per-rule tests for DF-026..030 — runtime-bypass ENV variables.

DF-026 (NODE_TLS_REJECT_UNAUTHORIZED=0),
DF-027 (PYTHONHTTPSVERIFY=0),
DF-028 (GIT_SSL_NO_VERIFY truthy),
DF-029 (REQUESTS_CA_BUNDLE empty / /dev/null),
DF-030 (NODE_OPTIONS with --require / --inspect).
"""
from .conftest import run_check

_DIGEST = "@sha256:" + "0" * 64


# ── DF-026 NODE_TLS_REJECT_UNAUTHORIZED ─────────────────────────────


class TestDF026:
    def test_fails_on_zero(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-026")
        assert not f.passed

    def test_passes_on_one(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_TLS_REJECT_UNAUTHORIZED=1
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-026")
        assert f.passed

    def test_passes_without_env(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-026")
        assert f.passed

    def test_passes_on_empty_assignment(self):
        # Explicitly clearing the variable is the documented way
        # to undo an inherited bypass from a base image.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_TLS_REJECT_UNAUTHORIZED=
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-026")
        assert f.passed


# ── DF-027 PYTHONHTTPSVERIFY ────────────────────────────────────────


class TestDF027:
    def test_fails_on_zero(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
ENV PYTHONHTTPSVERIFY=0
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-027")
        assert not f.passed

    def test_passes_on_one(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
ENV PYTHONHTTPSVERIFY=1
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-027")
        assert f.passed

    def test_passes_without_env(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-027")
        assert f.passed


# ── DF-028 GIT_SSL_NO_VERIFY ────────────────────────────────────────


class TestDF028:
    def test_fails_on_one(self):
        text = f"""\
FROM alpine{_DIGEST}
USER 1001
ENV GIT_SSL_NO_VERIFY=1
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-028")
        assert not f.passed

    def test_fails_on_true_string(self):
        text = f"""\
FROM alpine{_DIGEST}
USER 1001
ENV GIT_SSL_NO_VERIFY=true
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-028")
        assert not f.passed

    def test_passes_on_zero(self):
        text = f"""\
FROM alpine{_DIGEST}
USER 1001
ENV GIT_SSL_NO_VERIFY=0
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-028")
        assert f.passed

    def test_passes_without_env(self):
        text = f"""\
FROM alpine{_DIGEST}
USER 1001
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-028")
        assert f.passed


# ── DF-029 REQUESTS_CA_BUNDLE ───────────────────────────────────────


class TestDF029:
    def test_fails_on_dev_null(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
ENV REQUESTS_CA_BUNDLE=/dev/null
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-029")
        assert not f.passed

    def test_fails_on_empty(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
ENV REQUESTS_CA_BUNDLE=
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-029")
        assert not f.passed

    def test_passes_on_real_path(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-029")
        assert f.passed

    def test_passes_without_env(self):
        text = f"""\
FROM python:3.12{_DIGEST}
USER 1001
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-029")
        assert f.passed


# ── DF-030 NODE_OPTIONS unsafe flags ────────────────────────────────


class TestDF030:
    def test_fails_on_require_flag(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS=--require=/opt/preload.js
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed

    def test_fails_on_import_flag(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS=--import=/opt/preload.mjs
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed

    def test_fails_on_inspect_flag(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS=--inspect-brk=0.0.0.0:9229
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed

    def test_passes_on_memory_flag(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS=--max-old-space-size=2048
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert f.passed

    def test_passes_without_env(self):
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert f.passed

    def test_fails_on_unsafe_flag_among_safe_flags(self):
        # Multi-flag NODE_OPTIONS needs the quoted form so the ENV
        # parser keeps the whole value associated with NODE_OPTIONS;
        # the unquoted form gets split into separate key=value pairs
        # by Docker's ENV syntax.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS="--max-old-space-size=2048 --require=/opt/preload.js"
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed

    def test_fails_on_short_require_alias(self):
        # Node accepts ``-r <path>`` as the short form of
        # ``--require=<path>`` and honors it inside NODE_OPTIONS.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS="-r /opt/preload.js"
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed
        assert "-r" in f.description

    def test_fails_on_require_whitespace_form(self):
        # Node accepts ``--require <path>`` (space-separated) as
        # an equivalent of ``--require=<path>`` inside NODE_OPTIONS.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS="--require /opt/preload.js"
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed
        assert "--require" in f.description

    def test_fails_on_import_whitespace_form(self):
        # Same whitespace shape, but for the ESM ``--import`` flag.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS="--import /opt/preload.mjs"
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert not f.passed
        assert "--import" in f.description

    def test_passes_on_substring_lookalike(self):
        # Innocent flags that happen to contain ``-r`` as a substring
        # (``--enable-source-maps``) must not trigger the short alias
        # match.
        text = f"""\
FROM node:20{_DIGEST}
USER 1001
ENV NODE_OPTIONS="--enable-source-maps --unhandled-rejections=throw"
HEALTHCHECK CMD true
"""
        f = run_check(text, "DF-030")
        assert f.passed
