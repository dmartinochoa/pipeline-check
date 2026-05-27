"""GAR-001/002/003 -- Artifact Registry checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gar001_vuln_scanning,
    gar002_public_repo,
    gar003_cleanup,
)


def _repo(
    name: str = "projects/p/locations/us/repositories/docker-repo",
    *,
    fmt: str = "DOCKER",
    mode: str = "STANDARD_REPOSITORY",
    cleanup_policies: dict | None = None,
    scanning: str = "INHERITED",
) -> dict:
    return {
        "name": name,
        "format": fmt,
        "mode": mode,
        "cleanup_policies": cleanup_policies or {},
        "vulnerability_scanning_config": {
            "enablement_config": scanning,
        },
    }


# -----------------------------------------------------------------------
# GAR-001: repository has no vulnerability scanning
# -----------------------------------------------------------------------

class TestGAR001:
    def test_scanning_inherited_fails(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(scanning="INHERITED")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_scanning_disabled_fails(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(scanning="DISABLED")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_scanning_standard_passes(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(scanning="STANDARD")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_scanning_enabled_passes(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(scanning="ENABLED")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_non_docker_format_skipped(self, make_catalog):
        """Only DOCKER and UNKNOWN format repos are checked."""
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(fmt="MAVEN", scanning="INHERITED")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert findings == []

    def test_unknown_format_checked(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(fmt="UNKNOWN", scanning="INHERITED")],
        })
        findings = gar001_vuln_scanning.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_repos_returns_empty(self, make_catalog):
        cat = make_catalog(**{"artifactregistry:repos": []})
        assert gar001_vuln_scanning.check(cat) == []


# -----------------------------------------------------------------------
# GAR-002: repository is publicly readable
# -----------------------------------------------------------------------

class TestGAR002:
    def test_standard_repo_passes(self, make_catalog):
        """Current implementation always passes for standard repos."""
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(mode="STANDARD_REPOSITORY")],
        })
        findings = gar002_public_repo.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_virtual_repo_skipped(self, make_catalog):
        """VIRTUAL_REPOSITORY mode is skipped entirely."""
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(mode="VIRTUAL_REPOSITORY")],
        })
        findings = gar002_public_repo.check(cat)
        assert findings == []

    def test_remote_repo_passes(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(mode="REMOTE_REPOSITORY")],
        })
        findings = gar002_public_repo.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_repos_returns_empty(self, make_catalog):
        cat = make_catalog(**{"artifactregistry:repos": []})
        assert gar002_public_repo.check(cat) == []


# -----------------------------------------------------------------------
# GAR-003: repository has no cleanup policy
# -----------------------------------------------------------------------

class TestGAR003:
    def test_no_cleanup_policy_fails(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(cleanup_policies={})],
        })
        findings = gar003_cleanup.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert "no cleanup policy" in findings[0].description

    def test_has_cleanup_policy_passes(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(cleanup_policies={
                "delete-old": {"action": {"type": "Delete"}},
            })],
        })
        findings = gar003_cleanup.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True
        assert "1 cleanup" in findings[0].description

    def test_multiple_cleanup_policies_counted(self, make_catalog):
        cat = make_catalog(**{
            "artifactregistry:repos": [_repo(cleanup_policies={
                "p1": {"action": {"type": "Delete"}},
                "p2": {"action": {"type": "Keep"}},
            })],
        })
        findings = gar003_cleanup.check(cat)
        assert findings[0].passed is True
        assert "2 cleanup" in findings[0].description

    def test_no_repos_returns_empty(self, make_catalog):
        cat = make_catalog(**{"artifactregistry:repos": []})
        assert gar003_cleanup.check(cat) == []
