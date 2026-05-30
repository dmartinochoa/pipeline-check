"""Unit tests for the shared Go-module-verification primitive."""
from __future__ import annotations

from pipeline_check.core.checks._primitives.go_insecure_env import (
    insecure_settings_in_env,
    insecure_settings_in_script,
)


class TestEnvDict:
    def test_gosumdb_off_fires(self):
        assert insecure_settings_in_env({"GOSUMDB": "off"})

    def test_gosumdb_off_as_bool_fires(self):
        # YAML coerces bareword off -> False; quoted "off" stays str.
        assert insecure_settings_in_env({"GOSUMDB": False})

    def test_goflags_insecure_fires(self):
        assert insecure_settings_in_env({"GOFLAGS": "-insecure -mod=mod"})

    def test_gonosumcheck_truthy_fires(self):
        assert insecure_settings_in_env({"GONOSUMCHECK": "1"})

    def test_goinsecure_fires(self):
        assert insecure_settings_in_env({"GOINSECURE": "git.corp/*"})

    def test_broad_goprivate_fires(self):
        assert insecure_settings_in_env({"GOPRIVATE": "*"})

    def test_broad_goprivate_host_wildcard_fires(self):
        assert insecure_settings_in_env({"GOPRIVATE": "github.com/*"})

    def test_scoped_goprivate_passes(self):
        assert not insecure_settings_in_env({"GOPRIVATE": "github.com/myorg/*"})

    def test_goproxy_direct_not_flagged(self):
        assert not insecure_settings_in_env({"GOPROXY": "direct"})

    def test_goproxy_off_not_flagged(self):
        assert not insecure_settings_in_env({"GOPROXY": "off"})

    def test_clean_env_passes(self):
        assert not insecure_settings_in_env({"GOFLAGS": "-mod=readonly", "CI": "true"})

    def test_non_dict_is_safe(self):
        assert insecure_settings_in_env(None) == []
        assert insecure_settings_in_env("GOSUMDB=off") == []


class TestScript:
    def test_export_gosumdb_off_fires(self):
        assert insecure_settings_in_script("export GOSUMDB=off\ngo build ./...")

    def test_env_prefix_fires(self):
        assert insecure_settings_in_script("GOFLAGS=-insecure go build ./...")

    def test_quoted_value_fires(self):
        assert insecure_settings_in_script('export GOSUMDB="off"')

    def test_clean_script_passes(self):
        assert insecure_settings_in_script("go build ./...\nexport CGO_ENABLED=0") == []

    def test_scoped_goprivate_export_passes(self):
        assert insecure_settings_in_script("export GOPRIVATE=github.com/myorg/*") == []
