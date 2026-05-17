"""Per-rule tests for Dockerfile DF-024..025.

DF-024 (npm/yarn/pnpm install without --ignore-scripts),
DF-025 (.npmrc or pip credentials written into an image layer).
"""
from __future__ import annotations

from .conftest import run_check

# ── DF-024 npm install --ignore-scripts ──────────────────────────────


class TestDF024:
    def test_fails_on_npm_ci_without_ignore_scripts(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm ci
"""
        f = run_check(text, "DF-024")
        assert not f.passed
        assert "lifecycle scripts" in f.description.lower()

    def test_fails_on_npm_install_without_flag(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm install
"""
        f = run_check(text, "DF-024")
        assert not f.passed

    def test_fails_on_yarn_install(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN yarn install
"""
        f = run_check(text, "DF-024")
        assert not f.passed

    def test_fails_on_pnpm_install(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN pnpm install
"""
        f = run_check(text, "DF-024")
        assert not f.passed

    def test_passes_with_ignore_scripts_flag(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm ci --ignore-scripts
"""
        f = run_check(text, "DF-024")
        assert f.passed

    def test_passes_with_env_kill_switch(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV NPM_CONFIG_IGNORE_SCRIPTS=true
RUN npm ci
"""
        f = run_check(text, "DF-024")
        assert f.passed

    def test_passes_with_yarn_kill_switch(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
ENV YARN_ENABLE_SCRIPTS=false
RUN yarn install
"""
        f = run_check(text, "DF-024")
        assert f.passed

    def test_passes_with_global_install(self):
        # Global CLI installs don't pretend to be reproducible.
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN npm i -g typescript
"""
        f = run_check(text, "DF-024")
        assert f.passed

    def test_passes_without_node_tooling(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo hello
"""
        f = run_check(text, "DF-024")
        assert f.passed


# ── DF-025 .npmrc / pip credentials baked into layer ─────────────────


class TestDF025:
    def test_fails_on_npm_authtoken_echo(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > /root/.npmrc
"""
        f = run_check(text, "DF-025")
        assert not f.passed
        assert "npm auth line" in f.description.lower()

    def test_fails_on_npm_authtoken_append(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> /root/.npmrc
"""
        f = run_check(text, "DF-025")
        assert not f.passed

    def test_fails_on_npm_password_line(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo "//my-registry.example.com/:_password=hunter2" > /root/.npmrc
"""
        f = run_check(text, "DF-025")
        assert not f.passed

    def test_fails_on_pip_index_credentials(self):
        text = """\
FROM python:3.12@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo "index-url = https://user:pass@pypi.internal.example.com/simple" > /etc/pip.conf
"""
        f = run_check(text, "DF-025")
        assert not f.passed
        assert "pip" in f.description.lower()

    def test_passes_when_authline_not_redirected(self):
        # ``echo //registry/:_authToken=...`` printed to stdout (no
        # file redirect) doesn't persist into a layer.
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN echo "credentials must be mounted, not echoed"
"""
        f = run_check(text, "DF-025")
        assert f.passed

    def test_passes_with_buildkit_secret_mount(self):
        text = """\
FROM node:20@sha256:0000000000000000000000000000000000000000000000000000000000000001
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --ignore-scripts
"""
        f = run_check(text, "DF-025")
        assert f.passed
