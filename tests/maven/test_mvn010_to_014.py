"""Per-rule unit tests for MVN-010..014 (Maven extended pack)."""
from __future__ import annotations

from pipeline_check.core.checks.maven.base import MavenContext, _parse_pom
from pipeline_check.core.checks.maven.pipelines import MavenChecks

from .conftest import run_check


def _render_pom_with_build(build_xml: str) -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>\n"
        f"  <build>{build_xml}\n  </build>\n"
        "</project>\n"
    )


def _settings(servers_xml: str = "") -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<settings>\n"
        f"  <servers>{servers_xml}\n  </servers>\n"
        "</settings>\n"
    )


# ── MVN-010 ─────────────────────────────────────────────────────


class TestMVN010:
    def test_fires_on_plaintext_password(self):
        body = _settings(
            "\n    <server>"
            "\n      <id>corp-nexus</id>"
            "\n      <username>bot</username>"
            "\n      <password>s3cret</password>"
            "\n    </server>"
        )
        f = run_check(body, "MVN-010", path="settings.xml")
        assert not f.passed
        assert "corp-nexus" in f.description

    def test_passes_on_encrypted_password(self):
        body = _settings(
            "\n    <server>"
            "\n      <id>corp-nexus</id>"
            "\n      <username>bot</username>"
            "\n      <password>{COQLCE6DU6GtcS5P=}</password>"
            "\n    </server>"
        )
        f = run_check(body, "MVN-010", path="settings.xml")
        assert f.passed

    def test_passes_on_env_var_placeholder(self):
        body = _settings(
            "\n    <server>"
            "\n      <id>corp-nexus</id>"
            "\n      <password>${env.NEXUS_TOKEN}</password>"
            "\n    </server>"
        )
        f = run_check(body, "MVN-010", path="settings.xml")
        assert f.passed

    def test_skips_pom_files(self):
        # Non-settings.xml = not applicable.
        from .conftest import pom_with_dep
        body = pom_with_dep()
        f = run_check(body, "MVN-010")
        assert f.passed


# ── MVN-011 ─────────────────────────────────────────────────────


class TestMVN011:
    def test_fires_on_repo_url_credentials(self):
        from .conftest import pom_with_dep
        body = pom_with_dep(
            repositories=(
                "\n    <repository>"
                "\n      <id>corp</id>"
                "\n      <url>https://bot:secret@nexus.corp/repo</url>"
                "\n    </repository>"
            ),
        )
        f = run_check(body, "MVN-011")
        assert not f.passed
        assert "bot@nexus.corp" in f.description

    def test_passes_on_clean_url(self):
        from .conftest import pom_with_dep
        body = pom_with_dep(
            repositories=(
                "\n    <repository>"
                "\n      <id>corp</id>"
                "\n      <url>https://nexus.corp/repo</url>"
                "\n    </repository>"
            ),
        )
        f = run_check(body, "MVN-011")
        assert f.passed


# ── MVN-012 ─────────────────────────────────────────────────────


class TestMVN012:
    def test_fires_on_floating_plugin(self):
        body = _render_pom_with_build(
            "\n    <plugins>"
            "\n      <plugin>"
            "\n        <groupId>org.apache.maven.plugins</groupId>"
            "\n        <artifactId>maven-shade-plugin</artifactId>"
            "\n        <version>[3.0,4.0)</version>"
            "\n      </plugin>"
            "\n    </plugins>"
        )
        f = run_check(body, "MVN-012")
        assert not f.passed
        assert "maven-shade-plugin" in f.description

    def test_fires_on_missing_plugin_version(self):
        body = _render_pom_with_build(
            "\n    <plugins>"
            "\n      <plugin>"
            "\n        <groupId>org.apache.maven.plugins</groupId>"
            "\n        <artifactId>maven-shade-plugin</artifactId>"
            "\n      </plugin>"
            "\n    </plugins>"
        )
        f = run_check(body, "MVN-012")
        assert not f.passed

    def test_passes_on_exact_pin(self):
        body = _render_pom_with_build(
            "\n    <plugins>"
            "\n      <plugin>"
            "\n        <groupId>org.apache.maven.plugins</groupId>"
            "\n        <artifactId>maven-shade-plugin</artifactId>"
            "\n        <version>3.5.1</version>"
            "\n      </plugin>"
            "\n    </plugins>"
        )
        f = run_check(body, "MVN-012")
        assert f.passed

    def test_passes_on_no_build_section(self):
        from .conftest import pom_with_dep
        body = pom_with_dep()
        f = run_check(body, "MVN-012")
        assert f.passed


# ── MVN-013 ─────────────────────────────────────────────────────


class TestMVN013:
    def test_fires_on_floating_extension(self):
        body = _render_pom_with_build(
            "\n    <extensions>"
            "\n      <extension>"
            "\n        <groupId>org.apache.maven.wagon</groupId>"
            "\n        <artifactId>wagon-ssh</artifactId>"
            "\n        <version>[3.0,)</version>"
            "\n      </extension>"
            "\n    </extensions>"
        )
        f = run_check(body, "MVN-013")
        assert not f.passed
        assert "wagon-ssh" in f.description

    def test_passes_on_exact_pin(self):
        body = _render_pom_with_build(
            "\n    <extensions>"
            "\n      <extension>"
            "\n        <groupId>org.apache.maven.wagon</groupId>"
            "\n        <artifactId>wagon-ssh</artifactId>"
            "\n        <version>3.5.3</version>"
            "\n      </extension>"
            "\n    </extensions>"
        )
        f = run_check(body, "MVN-013")
        assert f.passed


# ── MVN-014 ─────────────────────────────────────────────────────


class TestMVN014:
    def test_passes_when_no_wrapper(self, tmp_path):
        # POM at tmp_path with no .mvn/wrapper directory => safe.
        from .conftest import pom_with_dep
        pom = tmp_path / "pom.xml"
        pom.write_text(pom_with_dep(), encoding="utf-8")
        ctx = MavenContext([_parse_pom(str(pom), pom.read_text(encoding="utf-8"))])
        f = next(
            f for f in MavenChecks(ctx).run() if f.check_id == "MVN-014"
        )
        assert f.passed

    def test_fires_when_wrapper_missing_hash(self, tmp_path):
        from .conftest import pom_with_dep
        pom = tmp_path / "pom.xml"
        pom.write_text(pom_with_dep(), encoding="utf-8")
        (tmp_path / ".mvn" / "wrapper").mkdir(parents=True)
        (tmp_path / ".mvn" / "wrapper" / "maven-wrapper.properties").write_text(
            "distributionUrl=https://internal/apache-maven-3.9.6-bin.zip\n",
            encoding="utf-8",
        )
        ctx = MavenContext([_parse_pom(str(pom), pom.read_text(encoding="utf-8"))])
        f = next(
            f for f in MavenChecks(ctx).run() if f.check_id == "MVN-014"
        )
        assert not f.passed
        assert "distributionSha256Sum" in f.description

    def test_passes_when_wrapper_has_hash(self, tmp_path):
        from .conftest import pom_with_dep
        pom = tmp_path / "pom.xml"
        pom.write_text(pom_with_dep(), encoding="utf-8")
        (tmp_path / ".mvn" / "wrapper").mkdir(parents=True)
        (tmp_path / ".mvn" / "wrapper" / "maven-wrapper.properties").write_text(
            "distributionUrl=https://repo.maven.apache.org/.../apache-maven-3.9.6-bin.zip\n"
            "distributionSha256Sum=" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        ctx = MavenContext([_parse_pom(str(pom), pom.read_text(encoding="utf-8"))])
        f = next(
            f for f in MavenChecks(ctx).run() if f.check_id == "MVN-014"
        )
        assert f.passed
