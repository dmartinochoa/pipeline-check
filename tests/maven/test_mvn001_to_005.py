"""Per-rule tests for MVN-001..005."""

from __future__ import annotations

from .conftest import pom_with_dep, run_check

# ── MVN-001 floating Maven version range ───────────────────────────────


class TestMVN001:
    def test_fails_on_bracket_range(self):
        text = pom_with_dep(version="[1.0,2.0)")
        f = run_check(text, "MVN-001")
        assert not f.passed
        assert "floating" in f.description

    def test_fails_on_open_range(self):
        text = pom_with_dep(version="[1.0,)")
        f = run_check(text, "MVN-001")
        assert not f.passed

    def test_fails_on_legacy_latest(self):
        text = pom_with_dep(version="LATEST")
        f = run_check(text, "MVN-001")
        assert not f.passed

    def test_passes_on_exact_pin(self):
        text = pom_with_dep(version="1.2.3")
        f = run_check(text, "MVN-001")
        assert f.passed

    def test_property_resolved_before_check(self):
        # Property points at a range; rule must catch the resolved value.
        text = pom_with_dep(
            version="${util.version}",
            properties="\n    <util.version>[1.0,2.0)</util.version>",
        )
        f = run_check(text, "MVN-001")
        assert not f.passed


# ── MVN-002 SNAPSHOT dependency ────────────────────────────────────────


class TestMVN002:
    def test_fails_on_snapshot(self):
        text = pom_with_dep(version="1.0.0-SNAPSHOT")
        f = run_check(text, "MVN-002")
        assert not f.passed
        assert "SNAPSHOT" in f.description

    def test_passes_on_release(self):
        text = pom_with_dep(version="1.0.0")
        f = run_check(text, "MVN-002")
        assert f.passed

    def test_property_resolved(self):
        text = pom_with_dep(
            version="${lib.version}",
            properties="\n    <lib.version>2.0.0-SNAPSHOT</lib.version>",
        )
        f = run_check(text, "MVN-002")
        assert not f.passed


# ── MVN-003 plaintext HTTP repository ──────────────────────────────────


class TestMVN003:
    def test_fails_on_http_repository(self):
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>insecure</id>\n"
                "      <url>http://repo.example.com/m2</url>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-003")
        assert not f.passed
        assert "http://" in f.description.lower() or "HTTP" in f.description

    def test_passes_on_https_repository(self):
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>secure</id>\n"
                "      <url>https://repo.example.com/m2</url>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-003")
        assert f.passed


# ── MVN-004 missing <version> ──────────────────────────────────────────


class TestMVN004:
    def test_fails_when_version_omitted(self):
        text = pom_with_dep(version=None)
        f = run_check(text, "MVN-004")
        assert not f.passed
        assert "version" in f.description.lower()

    def test_passes_when_version_present(self):
        text = pom_with_dep(version="1.0.0")
        f = run_check(text, "MVN-004")
        assert f.passed

    def test_managed_dependency_is_exempt(self):
        # An entry inside <dependencyManagement> without <version> is
        # NOT a real consumption; MVN-004 should pass.
        text = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencyManagement>\n"
            "    <dependencies>\n"
            "      <dependency>\n"
            "        <groupId>org.example</groupId>\n"
            "        <artifactId>lib</artifactId>\n"
            "        <version>1.0.0</version>\n"
            "      </dependency>\n"
            "    </dependencies>\n"
            "  </dependencyManagement>\n"
            "</project>\n"
        )
        f = run_check(text, "MVN-004")
        assert f.passed


# ── MVN-005 lax repository checksum policy ─────────────────────────────


class TestMVN005:
    def test_fails_on_explicit_warn(self):
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>internal</id>\n"
                "      <url>https://repo.internal.example.com/m2</url>\n"
                "      <releases>\n"
                "        <checksumPolicy>warn</checksumPolicy>\n"
                "      </releases>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-005")
        assert not f.passed
        assert "warn" in f.description

    def test_fails_on_missing_policy_for_non_central_repo(self):
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>internal</id>\n"
                "      <url>https://repo.internal.example.com/m2</url>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-005")
        assert not f.passed
        assert "no checksumPolicy" in f.description

    def test_passes_on_fail_policy(self):
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>internal</id>\n"
                "      <url>https://repo.internal.example.com/m2</url>\n"
                "      <releases>\n"
                "        <checksumPolicy>fail</checksumPolicy>\n"
                "      </releases>\n"
                "      <snapshots>\n"
                "        <checksumPolicy>fail</checksumPolicy>\n"
                "      </snapshots>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-005")
        assert f.passed

    def test_maven_central_is_exempt(self):
        # Central enforces checksums server-side; the policy is moot.
        text = pom_with_dep(
            repositories=(
                "\n    <repository>\n"
                "      <id>central</id>\n"
                "      <url>https://repo.maven.apache.org/maven2</url>\n"
                "    </repository>"
            ),
        )
        f = run_check(text, "MVN-005")
        assert f.passed
