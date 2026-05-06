"""Unit tests for DF-017 — ENV PATH prepends a world-writable directory."""
from __future__ import annotations

from pipeline_check.core.checks.dockerfile.base import (
    Dockerfile,
    parse_dockerfile,
)
from pipeline_check.core.checks.dockerfile.rules import (
    df017_env_path_writable as r17,
)


def _df(text: str) -> Dockerfile:
    return Dockerfile(
        path="Dockerfile",
        text=text,
        instructions=parse_dockerfile(text),
    )


class TestDF017EnvPathWritable:
    def test_fails_when_tmp_prepended_to_path(self):
        f = r17.check(_df(
            "FROM debian:12.5\n"
            "ENV PATH=/tmp:$PATH\n"
        ))
        assert not f.passed
        assert "/tmp" in f.description

    def test_fails_when_dev_shm_prepended(self):
        f = r17.check(_df(
            "FROM debian:12.5\n"
            "ENV PATH=/dev/shm/bin:/usr/bin\n"
        ))
        assert not f.passed
        assert "/dev/shm" in f.description

    def test_fails_when_var_tmp_subdir_prepended(self):
        f = r17.check(_df(
            "FROM debian:12.5\n"
            "ENV PATH=/var/tmp/bin:${PATH}\n"
        ))
        assert not f.passed

    def test_passes_when_path_appends_tmp_after_existing_path(self):
        # Writable dir AFTER $PATH is harmless because system bins
        # shadow whatever lands in /tmp.
        f = r17.check(_df(
            "FROM debian:12.5\n"
            "ENV PATH=$PATH:/tmp\n"
        ))
        assert f.passed

    def test_passes_when_path_unset(self):
        f = r17.check(_df("FROM debian:12.5\n"))
        assert f.passed

    def test_passes_when_path_only_holds_system_bins(self):
        f = r17.check(_df(
            "FROM debian:12.5\n"
            "ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        ))
        assert f.passed
