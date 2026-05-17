"""Per-rule tests for NPM-006 (compromised-package registry lookup).

The curated registry is the data layer the rule consumes; tests
exercise both the lookup helper (so a registry-data regression
trips the suite) and the rule against synthetic lockfiles.
"""

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.npm._compromised_packages import (
    known_names,
    lookup,
    registry_size,
)

from .conftest import run_check_lock

# ── Registry data layer ───────────────────────────────────────────────


class TestCompromisedRegistry:
    def test_registry_is_non_empty(self):
        # A passing registry-size-of-zero would make the rule a
        # silent no-op; guard against accidental deletions.
        assert registry_size() >= 5

    def test_known_names_include_canonical_incidents(self):
        names = known_names()
        # Canonical npm maintainer-takeover incidents the registry
        # was built around. If any of these drop out, the registry
        # has regressed.
        assert "event-stream" in names
        assert "ua-parser-js" in names
        assert "coa" in names
        assert "rc" in names
        assert "node-ipc" in names

    def test_lookup_hits_event_stream(self):
        hit = lookup("event-stream", "3.3.6")
        assert hit is not None
        assert "Copay" in hit.advisory or "flatmap-stream" in hit.advisory

    def test_lookup_misses_clean_version(self):
        # 3.3.7+ are the post-incident clean republishes.
        assert lookup("event-stream", "3.3.7") is None

    def test_lookup_is_case_insensitive_on_name(self):
        # npm package names are case-sensitive on the registry side
        # but cross-platform CI sometimes lowercases. Defensive.
        assert lookup("Event-Stream", "3.3.6") is not None

    def test_lookup_misses_unknown_package(self):
        assert lookup("lodash", "4.17.21") is None


# ── Rule behavior ─────────────────────────────────────────────────────


class TestNPM006:
    def test_fails_on_compromised_direct_dep(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/ua-parser-js": {
                    "version": "0.7.29",
                    "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        assert "ua-parser-js@0.7.29" in f.description

    def test_fails_on_compromised_transitive(self):
        # Compromised dep nested under another's node_modules — the
        # transitive shape pure SHA / lockfile pinning is blind to.
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/some-tool": {"version": "1.0.0"},
                "node_modules/some-tool/node_modules/coa": {
                    "version": "2.0.3",
                    "resolved": "https://registry.npmjs.org/coa/-/coa-2.0.3.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        assert "coa@2.0.3" in f.description

    def test_passes_on_clean_versions(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/ua-parser-js": {
                    "version": "1.0.40",
                    "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-1.0.40.tgz",
                    "integrity": "sha512-OK",
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-OK",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert f.passed

    def test_handles_legacy_v1_format(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "node-ipc": {
                    "version": "10.1.1",
                    "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-10.1.1.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        assert "node-ipc@10.1.1" in f.description

    def test_attaches_advisory_to_description(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/event-stream": {
                    "version": "3.3.6",
                    "resolved": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        # The advisory text or its citation should appear in the
        # description so the operator has a follow-up link.
        assert "event-stream" in f.description
        assert "Advisory:" in f.description

    def test_finding_severity_tracks_registry_entry_high(self):
        # node-ipc is registered as HIGH (protestware, scoped
        # destructive payload). A finding emitted solely for that
        # entry must report HIGH, not the rule-level CRITICAL.
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/node-ipc": {
                    "version": "10.1.1",
                    "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-10.1.1.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        assert f.severity == Severity.HIGH

    def test_finding_severity_escalates_to_critical_when_mixed(self):
        # node-ipc (HIGH) + ua-parser-js (CRITICAL) in the same lock:
        # the most severe entry wins so operators see CRITICAL.
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/node-ipc": {
                    "version": "10.1.1",
                    "resolved": "https://registry.npmjs.org/node-ipc/-/node-ipc-10.1.1.tgz",
                    "integrity": "sha512-FAKE",
                },
                "node_modules/ua-parser-js": {
                    "version": "0.7.29",
                    "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
                    "integrity": "sha512-FAKE",
                },
            },
        }
        f = run_check_lock(data, "NPM-006")
        assert not f.passed
        assert f.severity == Severity.CRITICAL
