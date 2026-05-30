"""Per-rule unit tests for MVN-015..018 (Maven build-RCE / deploy pack)."""
from __future__ import annotations

from pipeline_check.core.checks.maven.base import MavenContext, _parse_gradle
from pipeline_check.core.checks.maven.pipelines import MavenChecks

from .conftest import run_check


def _pom(body: str) -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>\n"
        f"{body}\n"
        "</project>\n"
    )


def _run_gradle(text: str, check_id: str, path: str = "build.gradle"):
    pom = _parse_gradle(path, text)
    for f in MavenChecks(MavenContext([pom])).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(f"{check_id} not produced")


# ── MVN-015 (build-time plugin exec) ────────────────────────────

_EXEC_EXECUTION = (
    "<executions><execution>"
    "<phase>generate-sources</phase>"
    "<goals><goal>exec</goal></goals>"
    "</execution></executions>"
)


class TestMVN015:
    def test_fires_on_exec_plugin_bound_to_phase(self):
        body = (
            "  <build><plugins><plugin>"
            "<groupId>org.codehaus.mojo</groupId>"
            "<artifactId>exec-maven-plugin</artifactId>"
            "<version>3.1.0</version>"
            f"{_EXEC_EXECUTION}"
            "</plugin></plugins></build>"
        )
        f = run_check(_pom(body), "MVN-015")
        assert not f.passed
        assert "exec-maven-plugin" in f.description

    def test_fires_on_antrun_plugin(self):
        body = (
            "  <build><plugins><plugin>"
            "<groupId>org.apache.maven.plugins</groupId>"
            "<artifactId>maven-antrun-plugin</artifactId>"
            "<version>3.1.0</version>"
            "<executions><execution><phase>package</phase>"
            "<goals><goal>run</goal></goals></execution></executions>"
            "</plugin></plugins></build>"
        )
        f = run_check(_pom(body), "MVN-015")
        assert not f.passed

    def test_passes_exec_plugin_without_executions(self):
        # Declared but not bound to the lifecycle (run manually only).
        body = (
            "  <build><plugins><plugin>"
            "<groupId>org.codehaus.mojo</groupId>"
            "<artifactId>exec-maven-plugin</artifactId>"
            "<version>3.1.0</version>"
            "</plugin></plugins></build>"
        )
        f = run_check(_pom(body), "MVN-015")
        assert f.passed

    def test_passes_on_ordinary_plugin(self):
        body = (
            "  <build><plugins><plugin>"
            "<groupId>org.apache.maven.plugins</groupId>"
            "<artifactId>maven-compiler-plugin</artifactId>"
            "<version>3.11.0</version>"
            "<executions><execution><phase>compile</phase>"
            "<goals><goal>compile</goal></goals></execution></executions>"
            "</plugin></plugins></build>"
        )
        f = run_check(_pom(body), "MVN-015")
        assert f.passed

    def test_passes_on_settings_xml(self):
        from .conftest import maven_ctx
        settings = "<settings><servers></servers></settings>"
        ctx = maven_ctx(settings, path="settings.xml")
        f = next(
            x for x in MavenChecks(ctx).run() if x.check_id == "MVN-015"
        )
        assert f.passed


# ── MVN-016 (gradle allowInsecureProtocol) ──────────────────────


class TestMVN016:
    def test_fires_on_groovy_flag(self):
        text = (
            "repositories {\n"
            "  maven {\n"
            "    url 'http://repo.internal/maven'\n"
            "    allowInsecureProtocol = true\n"
            "  }\n"
            "}\n"
        )
        f = _run_gradle(text, "MVN-016")
        assert not f.passed

    def test_fires_on_kotlin_is_flag(self):
        text = (
            "repositories {\n"
            "  maven {\n"
            "    url = uri(\"http://repo.internal/maven\")\n"
            "    isAllowInsecureProtocol = true\n"
            "  }\n"
            "}\n"
        )
        f = _run_gradle(text, "MVN-016", path="build.gradle.kts")
        assert not f.passed

    def test_passes_when_absent(self):
        text = "repositories {\n  mavenCentral()\n}\n"
        f = _run_gradle(text, "MVN-016")
        assert f.passed

    def test_skips_commented_flag(self):
        text = (
            "repositories {\n"
            "  // allowInsecureProtocol = true\n"
            "  mavenCentral()\n"
            "}\n"
        )
        f = _run_gradle(text, "MVN-016")
        assert f.passed

    def test_passes_on_pom_xml(self):
        f = run_check(_pom("  <build></build>"), "MVN-016")
        assert f.passed


# ── MVN-017 (settings.xml private key + passphrase) ─────────────


def _settings_server(server_body: str) -> str:
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<settings><servers>\n"
        f"<server>{server_body}</server>\n"
        "</servers></settings>\n"
    )


class TestMVN017:
    def test_fires_on_plaintext_passphrase(self):
        body = (
            "<id>release-host</id>"
            "<privateKey>/home/ci/.ssh/deploy</privateKey>"
            "<passphrase>hunter2</passphrase>"
        )
        f = run_check(_settings_server(body), "MVN-017", path="settings.xml")
        assert not f.passed
        assert "release-host" in f.description

    def test_passes_on_encrypted_passphrase(self):
        body = (
            "<id>release-host</id>"
            "<privateKey>/home/ci/.ssh/deploy</privateKey>"
            "<passphrase>{COQLCE6DU6GtcS5P=}</passphrase>"
        )
        f = run_check(_settings_server(body), "MVN-017", path="settings.xml")
        assert f.passed

    def test_passes_on_env_passphrase(self):
        body = (
            "<id>release-host</id>"
            "<privateKey>/home/ci/.ssh/deploy</privateKey>"
            "<passphrase>${env.DEPLOY_KEY_PASSPHRASE}</passphrase>"
        )
        f = run_check(_settings_server(body), "MVN-017", path="settings.xml")
        assert f.passed

    def test_passes_when_no_passphrase(self):
        body = (
            "<id>release-host</id>"
            "<privateKey>/home/ci/.ssh/deploy</privateKey>"
        )
        f = run_check(_settings_server(body), "MVN-017", path="settings.xml")
        assert f.passed

    def test_passes_on_pom_xml(self):
        f = run_check(_pom("  <build></build>"), "MVN-017")
        assert f.passed


# ── MVN-018 (distributionManagement release accepts snapshots) ──


class TestMVN018:
    def test_fires_on_release_repo_with_snapshots_enabled(self):
        body = (
            "  <distributionManagement>\n"
            "    <repository>\n"
            "      <id>corp-releases</id>\n"
            "      <url>https://nexus.corp/releases</url>\n"
            "      <snapshots><enabled>true</enabled></snapshots>\n"
            "    </repository>\n"
            "  </distributionManagement>"
        )
        f = run_check(_pom(body), "MVN-018")
        assert not f.passed
        assert "corp-releases" in f.description

    def test_passes_when_snapshots_disabled(self):
        body = (
            "  <distributionManagement>\n"
            "    <repository>\n"
            "      <id>corp-releases</id>\n"
            "      <url>https://nexus.corp/releases</url>\n"
            "      <snapshots><enabled>false</enabled></snapshots>\n"
            "    </repository>\n"
            "  </distributionManagement>"
        )
        f = run_check(_pom(body), "MVN-018")
        assert f.passed

    def test_passes_when_only_snapshot_repository_present(self):
        body = (
            "  <distributionManagement>\n"
            "    <repository>\n"
            "      <id>corp-releases</id>\n"
            "      <url>https://nexus.corp/releases</url>\n"
            "    </repository>\n"
            "    <snapshotRepository>\n"
            "      <id>corp-snapshots</id>\n"
            "      <url>https://nexus.corp/snapshots</url>\n"
            "    </snapshotRepository>\n"
            "  </distributionManagement>"
        )
        f = run_check(_pom(body), "MVN-018")
        assert f.passed

    def test_passes_when_no_distribution_management(self):
        f = run_check(_pom("  <build></build>"), "MVN-018")
        assert f.passed
