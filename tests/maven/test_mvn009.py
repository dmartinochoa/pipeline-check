"""Per-rule tests for MVN-009 (Maven OSV advisory lookup).

Validates that the check fires when the OSV advisory dict is populated
with a matching GAV coordinate, and passes when it's empty or when
the coordinate has no advisory.
"""
from __future__ import annotations

from pipeline_check.core.checks.maven.base import MavenContext, _parse_pom
from pipeline_check.core.checks.maven.pipelines import MavenChecks

from .conftest import pom_with_dep


def _ctx_from(text: str, path: str = "pom.xml") -> MavenContext:
    pom = _parse_pom(path, text)
    return MavenContext([pom])


def _run_mvn009(ctx: MavenContext):
    findings = [
        f for f in MavenChecks(ctx).run() if f.check_id == "MVN-009"
    ]
    assert len(findings) == 1, (
        "exactly one MVN-009 finding per pom expected"
    )
    return findings[0]


class TestMVN009:
    def test_passes_when_no_osv_data(self):
        text = pom_with_dep(version="1.2.3")
        ctx = _ctx_from(text)
        # No osv_advisories populated -> passes silently.
        f = _run_mvn009(ctx)
        assert f.passed

    def test_fails_when_advisory_matches(self):
        text = pom_with_dep(
            group_id="org.example", artifact_id="lib", version="1.2.3",
        )
        ctx = _ctx_from(text)
        ctx.osv_advisories = {
            ("org.example:lib", "1.2.3"): [
                {"id": "GHSA-xxxx-yyyy-zzzz"},
            ],
        }
        f = _run_mvn009(ctx)
        assert not f.passed
        assert "GHSA-xxxx-yyyy-zzzz" in f.description
        # The structured VulnRef the OpenVEX reporter / --vex consume.
        assert len(f.vulnerabilities) == 1
        vref = f.vulnerabilities[0]
        assert vref.vuln_id == "GHSA-xxxx-yyyy-zzzz"
        assert vref.purl == "pkg:maven/org.example/lib@1.2.3"

    def test_advisory_aliases_carried(self):
        text = pom_with_dep(
            group_id="org.example", artifact_id="lib", version="1.2.3",
        )
        ctx = _ctx_from(text)
        ctx.osv_advisories = {
            ("org.example:lib", "1.2.3"): [
                {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2021-1"]},
            ],
        }
        f = _run_mvn009(ctx)
        assert f.vulnerabilities[0].aliases == ("CVE-2021-1",)

    def test_passes_when_version_not_in_advisory(self):
        text = pom_with_dep(
            group_id="org.example", artifact_id="lib", version="2.0.0",
        )
        ctx = _ctx_from(text)
        ctx.osv_advisories = {
            ("org.example:lib", "1.2.3"): [
                {"id": "GHSA-xxxx-yyyy-zzzz"},
            ],
        }
        f = _run_mvn009(ctx)
        assert f.passed
