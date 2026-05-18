"""Shared helpers for Maven per-rule tests.

Each test builds an inline ``pom.xml`` or ``settings.xml`` body,
parses it through :func:`pipeline_check.core.checks.maven.base._parse_pom`,
wraps the result in a :class:`MavenContext`, and asks the
orchestrator for the named ``MVN-*`` finding.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.maven.base import MavenContext, _parse_pom
from pipeline_check.core.checks.maven.pipelines import MavenChecks


def maven_ctx(text: str, path: str = "pom.xml") -> MavenContext:
    """Build a MavenContext from a single pom.xml / settings.xml body."""
    pom = _parse_pom(path, text)
    return MavenContext([pom])


def run_check(text: str, check_id: str, path: str = "pom.xml") -> Any:
    """Run every maven check; return the Finding with the given id."""
    ctx = maven_ctx(text, path=path)
    for f in MavenChecks(ctx).run():
        if f.check_id == check_id:
            return f
    raise AssertionError(
        f"check_id {check_id!r} not produced for the pom input"
    )


def pom_with_dep(
    group_id: str = "org.example",
    artifact_id: str = "lib",
    version: str | None = "1.0.0",
    *,
    extra_deps: str = "",
    properties: str = "",
    repositories: str = "",
) -> str:
    """Render a minimal pom.xml carrying one dependency plus optional extras."""
    version_xml = (
        f"\n      <version>{version}</version>" if version is not None else ""
    )
    props_xml = f"\n  <properties>{properties}\n  </properties>" if properties else ""
    repos_xml = (
        f"\n  <repositories>{repositories}\n  </repositories>"
        if repositories else ""
    )
    return (
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>"
        + props_xml
        + "\n  <dependencies>\n"
        + f"    <dependency>\n      <groupId>{group_id}</groupId>\n"
        + f"      <artifactId>{artifact_id}</artifactId>{version_xml}\n"
        + "    </dependency>\n"
        + extra_deps
        + "  </dependencies>"
        + repos_xml
        + "\n</project>\n"
    )
