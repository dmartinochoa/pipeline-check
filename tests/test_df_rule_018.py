"""Unit tests for DF-018 — RUN chown rewrites system-path ownership."""
from __future__ import annotations

from pipeline_check.core.checks.dockerfile.base import (
    Dockerfile,
    parse_dockerfile,
)
from pipeline_check.core.checks.dockerfile.rules import (
    df018_chown_system_path as r18,
)


def _df(text: str) -> Dockerfile:
    return Dockerfile(
        path="Dockerfile",
        text=text,
        instructions=parse_dockerfile(text),
    )


class TestDF018ChownSystemPath:
    def test_fails_on_chown_recursive_etc(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chown -R 1001:1001 /etc/myapp\n"
        ))
        assert not f.passed
        assert "/etc/myapp" in f.description

    def test_fails_on_chown_usr_local(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chown nobody /usr/local/bin/tool\n"
        ))
        assert not f.passed

    def test_fails_on_chgrp_lib(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chgrp -R appgroup /lib/myapp\n"
        ))
        assert not f.passed

    def test_passes_on_chown_under_app_dir(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN mkdir -p /app && chown -R 1001:1001 /app\n"
        ))
        assert f.passed

    def test_passes_on_chown_under_srv(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chown -R appuser:appgroup /srv/app\n"
        ))
        assert f.passed

    def test_passes_on_chown_var_lib_app(self):
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chown -R 1001:1001 /var/lib/myapp\n"
        ))
        assert f.passed

    def test_passes_on_chown_usr_src_app(self):
        # The official ``node`` image documents ``/usr/src/app`` as the
        # WORKDIR; ``chown -R node:node /usr/src/app`` is the standard,
        # safe pattern (source tree, no trusted binaries on PATH).
        f = r18.check(_df(
            "FROM node:20\n"
            "RUN chown -R node:node /usr/src/app\n"
        ))
        assert f.passed

    def test_passes_on_chown_usr_share_webroot(self):
        f = r18.check(_df(
            "FROM nginx:1.27\n"
            "RUN chown -R nginx:nginx /usr/share/nginx/html\n"
        ))
        assert f.passed

    def test_still_fails_on_chown_usr_local_bin(self):
        # The carve-out must not leak into the executable dirs.
        f = r18.check(_df(
            "FROM debian:12.5\n"
            "RUN chown -R app:app /usr/local/bin\n"
        ))
        assert not f.passed

    def test_passes_when_no_chown(self):
        f = r18.check(_df("FROM debian:12.5\nRUN echo hello\n"))
        assert f.passed
