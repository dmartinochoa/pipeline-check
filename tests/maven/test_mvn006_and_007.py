"""Per-rule tests for MVN-006 (compromised-package registry) and
MVN-007 (settings.xml wildcard mirror)."""
from __future__ import annotations

from .conftest import pom_with_dep, run_check


# ── MVN-006 compromised-package registry ───────────────────────────────


class TestMVN006:
    def test_fails_on_log4shell_version(self):
        text = pom_with_dep(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            version="2.14.1",
        )
        f = run_check(text, "MVN-006")
        assert not f.passed
        assert "log4j-core" in f.description.lower()
        assert "CVE-2021-44228" in f.description

    def test_passes_on_post_incident_version(self):
        text = pom_with_dep(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            version="2.17.1",
        )
        f = run_check(text, "MVN-006")
        assert f.passed

    def test_property_resolved_before_lookup(self):
        text = pom_with_dep(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            version="${log4j.version}",
            properties="\n    <log4j.version>2.14.1</log4j.version>",
        )
        f = run_check(text, "MVN-006")
        assert not f.passed

    def test_passes_on_unknown_artifact(self):
        text = pom_with_dep(
            group_id="org.example",
            artifact_id="not-in-registry",
            version="1.0.0",
        )
        f = run_check(text, "MVN-006")
        assert f.passed

    def test_settings_file_short_circuits(self):
        settings = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<settings xmlns='http://maven.apache.org/SETTINGS/1.0.0'>\n"
            "</settings>\n"
        )
        f = run_check(settings, "MVN-006", path="settings.xml")
        assert f.passed


# ── MVN-007 settings.xml wildcard mirror ───────────────────────────────


class TestMVN007:
    def test_fails_on_star_mirror(self):
        text = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<settings xmlns='http://maven.apache.org/SETTINGS/1.0.0'>\n"
            "  <mirrors>\n"
            "    <mirror>\n"
            "      <id>universal</id>\n"
            "      <url>https://nexus.example.com/repo</url>\n"
            "      <mirrorOf>*</mirrorOf>\n"
            "    </mirror>\n"
            "  </mirrors>\n"
            "</settings>\n"
        )
        f = run_check(text, "MVN-007", path="settings.xml")
        assert not f.passed
        assert "mirrorOf=*" in f.description

    def test_fails_on_external_star_mirror(self):
        text = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<settings xmlns='http://maven.apache.org/SETTINGS/1.0.0'>\n"
            "  <mirrors>\n"
            "    <mirror>\n"
            "      <id>external</id>\n"
            "      <url>https://nexus.example.com/repo</url>\n"
            "      <mirrorOf>external:*</mirrorOf>\n"
            "    </mirror>\n"
            "  </mirrors>\n"
            "</settings>\n"
        )
        f = run_check(text, "MVN-007", path="settings.xml")
        assert not f.passed

    def test_passes_on_central_only_mirror(self):
        text = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<settings xmlns='http://maven.apache.org/SETTINGS/1.0.0'>\n"
            "  <mirrors>\n"
            "    <mirror>\n"
            "      <id>central-only</id>\n"
            "      <url>https://nexus.example.com/repo</url>\n"
            "      <mirrorOf>central</mirrorOf>\n"
            "    </mirror>\n"
            "  </mirrors>\n"
            "</settings>\n"
        )
        f = run_check(text, "MVN-007", path="settings.xml")
        assert f.passed

    def test_pom_with_no_mirrors_block_passes(self):
        text = pom_with_dep(version="1.0.0")
        f = run_check(text, "MVN-007")
        assert f.passed
