"""Gradle (build.gradle / build.gradle.kts) parser tests.

Two layers:

1. ``_parse_gradle`` unit tests: coordinate strings, map-form deps,
   maven { url ... } repositories, single-arg ``maven("...")``
   shorthand, dedup behavior.
2. End-to-end through ``MavenContext.from_path``: a real
   build.gradle / build.gradle.kts on disk produces a
   :class:`PomFile` whose tuples flow through MVN-001 / MVN-002 /
   MVN-003 / MVN-006 unchanged.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from pipeline_check.core.checks.maven.base import (
    MavenContext,
    _parse_gradle,
)
from pipeline_check.core.checks.maven.pipelines import MavenChecks

# ── _parse_gradle ──────────────────────────────────────────────────


class TestParseGradle:
    def test_coordinate_string_groovy(self) -> None:
        body = textwrap.dedent(
            """\
            dependencies {
                implementation 'org.apache.commons:commons-text:1.10.0'
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        assert len(pf.dependencies) == 1
        dep = pf.dependencies[0]
        assert dep.group_id == "org.apache.commons"
        assert dep.artifact_id == "commons-text"
        assert dep.version == "1.10.0"

    def test_coordinate_string_kotlin(self) -> None:
        body = textwrap.dedent(
            """\
            dependencies {
                implementation("org.apache.commons:commons-text:1.10.0")
            }
            """
        )
        pf = _parse_gradle("build.gradle.kts", body)
        assert len(pf.dependencies) == 1
        assert pf.dependencies[0].artifact_id == "commons-text"

    def test_classifier_suffix_dropped_from_version(self) -> None:
        # ``:sources`` / ``@war`` etc. after the version are
        # consumed and not folded back into the version literal.
        body = textwrap.dedent(
            """\
            dependencies {
                implementation 'org.example:foo:1.2.3:sources'
                implementation "org.example:bar:1.2.3@war"
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        versions = {d.version for d in pf.dependencies}
        assert versions == {"1.2.3"}

    def test_map_form_dependency(self) -> None:
        body = textwrap.dedent(
            """\
            dependencies {
                api group: 'org.springframework', name: 'spring-beans', version: '5.3.20'
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        assert len(pf.dependencies) == 1
        d = pf.dependencies[0]
        assert (d.group_id, d.artifact_id, d.version) == (
            "org.springframework", "spring-beans", "5.3.20",
        )

    def test_map_form_kotlin_assignment(self) -> None:
        body = textwrap.dedent(
            """\
            dependencies {
                api(group = "org.springframework", name = "spring-beans", version = "5.3.20")
            }
            """
        )
        pf = _parse_gradle("build.gradle.kts", body)
        assert pf.dependencies[0].artifact_id == "spring-beans"

    def test_map_form_dependency_order_insensitive(self) -> None:
        # Gradle named arguments are unordered (both Groovy and
        # Kotlin DSL), so all six permutations must produce the
        # same coordinate.
        permutations = [
            "group: 'org.example', name: 'lib', version: '1.0'",
            "group: 'org.example', version: '1.0', name: 'lib'",
            "name: 'lib', group: 'org.example', version: '1.0'",
            "name: 'lib', version: '1.0', group: 'org.example'",
            "version: '1.0', group: 'org.example', name: 'lib'",
            "version: '1.0', name: 'lib', group: 'org.example'",
        ]
        for line in permutations:
            body = textwrap.dedent(
                f"""\
                dependencies {{
                    api {line}
                }}
                """
            )
            pf = _parse_gradle("build.gradle", body)
            assert len(pf.dependencies) == 1, line
            d = pf.dependencies[0]
            assert (d.group_id, d.artifact_id, d.version) == (
                "org.example", "lib", "1.0",
            ), line

    def test_map_form_kotlin_multiline_order_insensitive(self) -> None:
        # Kotlin DSL commonly wraps map-style deps over several
        # lines; named args still need to match in any order.
        body = textwrap.dedent(
            """\
            dependencies {
                api(
                    version = "5.3.20",
                    name = "spring-beans",
                    group = "org.springframework",
                )
            }
            """
        )
        pf = _parse_gradle("build.gradle.kts", body)
        assert len(pf.dependencies) == 1
        d = pf.dependencies[0]
        assert (d.group_id, d.artifact_id, d.version) == (
            "org.springframework", "spring-beans", "5.3.20",
        )

    def test_map_form_incomplete_drops_silently(self) -> None:
        # Two-key shorthands ({group, name} or {group, version}) are
        # parsed elsewhere; the map-form regex requires all three.
        body = textwrap.dedent(
            """\
            dependencies {
                api group: 'org.example', name: 'foo'
                api group: 'org.example', version: '1.0'
                api name: 'foo', name: 'foo', name: 'foo'
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        assert len(pf.dependencies) == 0

    def test_dedup_when_same_coordinate_appears_twice(self) -> None:
        body = textwrap.dedent(
            """\
            dependencies {
                implementation 'org.example:foo:1.0.0'
                testImplementation 'org.example:foo:1.0.0'
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        assert len(pf.dependencies) == 1

    def test_maven_repo_url_groovy(self) -> None:
        body = textwrap.dedent(
            """\
            repositories {
                mavenCentral()
                maven { url 'http://example.com/repo' }
                maven { url "https://internal/maven" }
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        urls = {r.url for r in pf.repositories}
        assert urls == {
            "http://example.com/repo", "https://internal/maven",
        }

    def test_maven_repo_url_kotlin_uri_wrapper(self) -> None:
        body = textwrap.dedent(
            """\
            repositories {
                maven { url = uri("http://example.com/repo") }
            }
            """
        )
        pf = _parse_gradle("build.gradle.kts", body)
        assert pf.repositories[0].url == "http://example.com/repo"

    def test_maven_single_arg_shorthand(self) -> None:
        body = textwrap.dedent(
            """\
            repositories {
                maven("http://internal.example.com/m2")
            }
            """
        )
        pf = _parse_gradle("build.gradle.kts", body)
        assert pf.repositories[0].url == (
            "http://internal.example.com/m2"
        )

    def test_variable_substitution_left_unresolved(self) -> None:
        # ${junitVersion} is preserved verbatim — MVN-001 will then
        # flag it as a dynamic version since ${...} isn't a clean
        # release-version literal. Documented limitation; resolving
        # ``ext { junitVersion = "..." }`` is a follow-up.
        body = textwrap.dedent(
            """\
            ext {
                junitVersion = '4.13.2'
            }
            dependencies {
                testImplementation "junit:junit:${junitVersion}"
            }
            """
        )
        pf = _parse_gradle("build.gradle", body)
        assert len(pf.dependencies) == 1
        assert pf.dependencies[0].version == "${junitVersion}"

    def test_parsed_ok_always_true(self) -> None:
        # Even on garbage input (no dependencies / repositories
        # blocks at all), the parser returns parsed_ok=True with
        # empty tuples — there's no XML-style parse-failure path.
        pf = _parse_gradle("build.gradle", "// just a comment\n")
        assert pf.parsed_ok is True
        assert pf.dependencies == ()
        assert pf.repositories == ()


# ── Integration: end-to-end via MavenContext.from_path ───────────


_GRADLE_BODY = textwrap.dedent(
    """\
    plugins {
        id 'java'
    }

    repositories {
        mavenCentral()
        maven { url 'http://internal.example.com/m2' }
    }

    dependencies {
        implementation 'org.apache.commons:commons-text:1.10.0'
        implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    }
    """
)


def _write_build_gradle(tmp_path: Path) -> Path:
    target = tmp_path / "build.gradle"
    target.write_text(_GRADLE_BODY, encoding="utf-8")
    return target


def test_build_gradle_picked_up_by_loader(tmp_path: Path) -> None:
    _write_build_gradle(tmp_path)
    ctx = MavenContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    pf = ctx.files[0]
    coords = {(d.group_id, d.artifact_id) for d in pf.dependencies}
    assert ("org.apache.commons", "commons-text") in coords
    assert ("org.apache.logging.log4j", "log4j-core") in coords


def test_build_gradle_mvn003_fires_on_http_repository(
    tmp_path: Path,
) -> None:
    _write_build_gradle(tmp_path)
    ctx = MavenContext.from_path(tmp_path)
    findings = list(MavenChecks(ctx).run())
    mvn003 = [f for f in findings if f.check_id == "MVN-003"]
    assert mvn003 and not mvn003[0].passed
    # Assert the full URL (not just a host substring) so CodeQL's
    # py/incomplete-url-substring-sanitization rule doesn't flag this
    # as a sanitization bypass pattern — the test is verifying the
    # finding's prose mentions the offending repo, no sanitization
    # is happening here.
    assert "http://internal.example.com/m2" in mvn003[0].description


def test_build_gradle_mvn006_flags_compromised_version(
    tmp_path: Path,
) -> None:
    _write_build_gradle(tmp_path)  # pins log4j-core 2.14.1
    ctx = MavenContext.from_path(tmp_path)
    findings = list(MavenChecks(ctx).run())
    mvn006 = [f for f in findings if f.check_id == "MVN-006"]
    assert mvn006 and not mvn006[0].passed
    assert "log4j-core" in mvn006[0].description


def test_build_gradle_kts_picked_up_by_loader(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        plugins {
            kotlin("jvm") version "1.9.0"
        }

        repositories {
            mavenCentral()
            maven { url = uri("https://example.com/repo") }
        }

        dependencies {
            implementation("org.apache.commons:commons-text:1.10.0")
        }
        """
    )
    (tmp_path / "build.gradle.kts").write_text(body, encoding="utf-8")
    ctx = MavenContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    pf = ctx.files[0]
    assert pf.dependencies[0].artifact_id == "commons-text"
    assert pf.repositories[0].url == "https://example.com/repo"


def test_build_gradle_skipped_under_build_dir(tmp_path: Path) -> None:
    # Files under ``build/`` are skipped (Gradle's output dir);
    # ``.gradle/`` (cache) too.
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "build.gradle").write_text(
        "dependencies { implementation 'x:y:1' }", encoding="utf-8",
    )
    (tmp_path / "build.gradle").write_text(
        "dependencies { implementation 'real:dep:2' }", encoding="utf-8",
    )
    ctx = MavenContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    assert ctx.files[0].dependencies[0].artifact_id == "dep"
