"""Regression tests from the rule audit (Buildkite FN / example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.buildkite.rules import (
    bk005_docker_privileged as bk005,
)
from pipeline_check.core.checks.buildkite.rules import (
    taint005_metadata_taint as taint005,
)


def _halves(rule):
    """Split a RULE.exploit_example into (vulnerable_doc, safe_doc)."""
    vuln, safe = rule.exploit_example.split("\n\n", 1)
    return yaml.safe_load(vuln), yaml.safe_load(safe)


class TestTAINT005MetadataTaint:
    def test_pull_request_title_is_a_tainted_source(self):
        # BUILDKITE_PULL_REQUEST_TITLE is the documented canonical
        # injection source; it was missing from the tainted-var set.
        doc = yaml.safe_load(
            'steps:\n'
            '  - command: buildkite-agent meta-data set "t" "$BUILDKITE_PULL_REQUEST_TITLE"\n'
            '  - command: |\n'
            '      T=$(buildkite-agent meta-data get t)\n'
            '      echo $T\n'
        )
        assert taint005.check("pipeline.yml", doc).passed is False


class TestBK005DockerPrivileged:
    def test_privileged_docker_plugin_fires(self):
        # The danger can be expressed through the docker plugin config
        # (privileged: true / host socket mount), not only a command.
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: ./it.sh\n"
            "    plugins:\n"
            "      - docker#v5.10.0:\n"
            "          image: app\n"
            "          privileged: true\n"
        )
        assert bk005.check("pipeline.yml", doc).passed is False

    def test_docker_sock_mount_fires(self):
        doc = yaml.safe_load(
            "steps:\n"
            "  - command: ./it.sh\n"
            "    plugins:\n"
            "      - docker#v5.10.0:\n"
            "          image: app\n"
            "          volumes:\n"
            "            - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        assert bk005.check("pipeline.yml", doc).passed is False

    def test_exploit_example_strong_check(self):
        vuln, safe = _halves(bk005.RULE)
        assert bk005.check("pipeline.yml", vuln).passed is False
        assert bk005.check("pipeline.yml", safe).passed is True
