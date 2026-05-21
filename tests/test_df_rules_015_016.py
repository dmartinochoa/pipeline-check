"""Unit tests for the two new Dockerfile rules added in v0.4.0.

DF-015 ``RUN`` chmod 777 / a+w; DF-016 missing OCI provenance labels.

Pattern: build a ``Dockerfile`` directly from inline source, run the
rule's ``check()``, assert ``passed``. Mirrors the existing fixture-
level tests but at a per-rule grain so failure modes are obvious in
isolation.
"""
from __future__ import annotations

from pipeline_check.core.checks.dockerfile.base import (
    Dockerfile,
    parse_dockerfile,
)
from pipeline_check.core.checks.dockerfile.rules import (
    df015_chmod_world_writable as r15,
)
from pipeline_check.core.checks.dockerfile.rules import (
    df016_missing_oci_provenance as r16,
)


def _df(text: str) -> Dockerfile:
    return Dockerfile(
        path="Dockerfile",
        text=text,
        instructions=parse_dockerfile(text),
    )


# ── DF-015 ────────────────────────────────────────────────────────────


class TestDF015ChmodWorldWritable:
    def test_fails_on_chmod_777(self):
        f = r15.check(_df("FROM x\nRUN chmod 777 /opt/data\n"))
        assert not f.passed
        assert "chmod 777" in f.description

    def test_fails_on_chmod_0777(self):
        f = r15.check(_df("FROM x\nRUN chmod 0777 /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_a_plus_w(self):
        f = r15.check(_df("FROM x\nRUN chmod a+w /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_a_plus_rwx(self):
        f = r15.check(_df("FROM x\nRUN chmod a+rwx /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_ugo_plus_w(self):
        f = r15.check(_df("FROM x\nRUN chmod ugo+w /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_o_plus_w(self):
        # ``o`` is the world (others) bit; ``o+w`` grants world-write
        # without granting it to user or group.
        f = r15.check(_df("FROM x\nRUN chmod o+w /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_a_plus_wx(self):
        # The mode part may carry ``w`` mixed with other flags in any
        # order: ``a+wx``, ``a+rw``, ``a+wrx``, ``+rwx`` all grant world
        # write, the older regex only caught ``a+w`` / ``a+rwx``.
        f = r15.check(_df("FROM x\nRUN chmod a+wx /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_bare_plus_wx(self):
        f = r15.check(_df("FROM x\nRUN chmod +wx /opt/data\n"))
        assert not f.passed

    def test_fails_on_chmod_go_plus_w(self):
        # ``go+w`` grants group + world write via the ``o`` bit.
        f = r15.check(_df("FROM x\nRUN chmod go+w /opt/data\n"))
        assert not f.passed

    def test_passes_on_chmod_u_plus_w(self):
        # ``u+w`` only grants the owner write; not a world-writable bit.
        f = r15.check(_df("FROM x\nRUN chmod u+w /opt/data\n"))
        assert f.passed

    def test_passes_on_chmod_g_plus_w(self):
        # ``g+w`` only grants the group write; not a world-writable bit.
        f = r15.check(_df("FROM x\nRUN chmod g+w /opt/data\n"))
        assert f.passed

    def test_passes_on_chmod_755(self):
        f = r15.check(_df("FROM x\nRUN chmod 755 /opt/data\n"))
        assert f.passed

    def test_passes_on_chmod_640(self):
        f = r15.check(_df("FROM x\nRUN chmod 640 /opt/data\n"))
        assert f.passed

    def test_passes_on_no_chmod_at_all(self):
        f = r15.check(_df("FROM x\nRUN echo hi\n"))
        assert f.passed

    def test_fails_when_chmod_appears_after_other_commands(self):
        # The literal pattern only requires word-boundary matching, so
        # multi-step RUN bodies are checked too.
        text = (
            "FROM x\n"
            "RUN apt-get install -y curl && \\\n"
            "    chmod 777 /opt/cache\n"
        )
        f = r15.check(_df(text))
        assert not f.passed


# ── DF-016 ────────────────────────────────────────────────────────────


class TestDF016MissingOCIProvenance:
    def test_fails_when_no_label_lines(self):
        f = r16.check(_df("FROM x\nCMD [\"a\"]\n"))
        assert not f.passed
        assert "image.source" in f.description
        assert "image.revision" in f.description

    def test_fails_when_only_unrelated_labels_present(self):
        text = (
            "FROM x\n"
            "LABEL maintainer=\"team@example.com\"\n"
        )
        f = r16.check(_df(text))
        assert not f.passed

    def test_fails_when_only_one_required_label_present(self):
        text = (
            "FROM x\n"
            "LABEL org.opencontainers.image.source=\"https://github.com/x/y\"\n"
        )
        f = r16.check(_df(text))
        assert not f.passed
        assert "image.revision" in f.description

    def test_passes_with_both_required_labels_on_one_line(self):
        text = (
            "FROM x\n"
            "LABEL "
            "org.opencontainers.image.source=\"https://github.com/x/y\" "
            "org.opencontainers.image.revision=\"abc\"\n"
        )
        f = r16.check(_df(text))
        assert f.passed

    def test_passes_with_required_labels_split_across_lines(self):
        text = (
            "FROM x\n"
            "LABEL org.opencontainers.image.source=\"https://github.com/x/y\"\n"
            "LABEL org.opencontainers.image.revision=\"abc\"\n"
        )
        f = r16.check(_df(text))
        assert f.passed

    def test_passes_with_continuation_lines(self):
        # Backslash line-continuation should still parse both labels.
        text = (
            "FROM x\n"
            "LABEL org.opencontainers.image.source=\"https://github.com/x/y\" \\\n"
            "      org.opencontainers.image.revision=\"abc\"\n"
        )
        f = r16.check(_df(text))
        assert f.passed
