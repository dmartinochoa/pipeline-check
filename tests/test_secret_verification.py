"""Tests for the live secret-verification pipeline.

All HTTP probes are mocked — no real network calls are made.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from pipeline_check.core.checks._primitives.secret_verifiers import (
    VerifyOutcome,
    get_verifier,
    has_verifier,
    redact_identity,
    verify_token,
)
from pipeline_check.core.checks._primitives.secret_verifiers._http import (
    ProbeResponse,
)
from pipeline_check.core.checks._secrets import classify_tokens_raw

# ── classify_tokens_raw ─────────────────────────────────────────────


class TestClassifyTokensRaw:
    def test_returns_detector_and_raw_value(self) -> None:
        doc = {"env": {"TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}
        result = classify_tokens_raw(doc)
        assert len(result) == 1
        assert result[0][0] == "github_token"
        assert result[0][1] == "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

    def test_multiple_tokens(self) -> None:
        doc = {
            "env": {
                "GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                "NPM": "npm_abcdefghijklmnopqrstuvwxyz1234567890",
            }
        }
        result = classify_tokens_raw(doc)
        detectors = {r[0] for r in result}
        assert "github_token" in detectors
        assert "npm_token" in detectors

    def test_deduplicates(self) -> None:
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        doc = {"a": token, "b": token}
        result = classify_tokens_raw(doc)
        assert len(result) == 1

    def test_skips_placeholder(self) -> None:
        doc = {"env": {"KEY": "ghp_placeholder_placeholder_placeholder00"}}
        result = classify_tokens_raw(doc)
        assert len(result) == 0

    def test_pre_collected_strings(self) -> None:
        tokens = ["ghp_abcdefghijklmnopqrstuvwxyz1234567890"]
        result = classify_tokens_raw(tokens)
        assert len(result) == 1
        assert result[0][0] == "github_token"

    def test_empty_doc(self) -> None:
        assert classify_tokens_raw({}) == []


# ── Verifier registry ───────────────────────────────────────────────


class TestVerifierRegistry:
    def test_has_verifier_for_known_detectors(self) -> None:
        for det in [
            "github_token", "npm_token", "slack_token",
            "anthropic_api_key", "openai_api_key",
            "stripe_secret", "gitlab_pat",
            "docker_hub_pat", "pypi_token",
            "google_api_key", "jwt",
            "digitalocean_token", "netlify_token",
            "terraform_cloud_token", "linear_api_key",
            "atlassian_api_token", "asana_pat",
            "new_relic_api_key", "telegram_bot_token",
            "replicate_token", "cohere_api_key",
            "mailchimp_api_key", "square_access_token",
        ]:
            assert has_verifier(det), f"missing verifier for {det}"

    def test_no_verifier_for_unknown(self) -> None:
        assert not has_verifier("made_up_detector_xyz")

    def test_get_verifier_returns_instance(self) -> None:
        v = get_verifier("github_token")
        assert v is not None
        assert hasattr(v, "probe")


# ── redact_identity ─────────────────────────────────────────────────


class TestRedactIdentity:
    def test_none(self) -> None:
        assert redact_identity(None) is None

    def test_short(self) -> None:
        assert redact_identity("abc") == "ab***"

    def test_long(self) -> None:
        assert redact_identity("github-user:octocat") == "gith***at"


# ── GitHub verifier ─────────────────────────────────────────────────


class TestGitHubVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"login": "octocat"}).encode(),
        )
        v = get_verifier("github_token")
        assert v is not None
        result = v.probe("ghp_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert result.identity == "github-user:octocat"

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=401, body=b"Bad credentials",
        )
        v = get_verifier("github_token")
        assert v is not None
        result = v.probe("ghp_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_unknown_on_server_error(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=500, body=b"")
        v = get_verifier("github_token")
        assert v is not None
        result = v.probe("ghp_fake")
        assert result.outcome == VerifyOutcome.UNKNOWN


# ── NPM verifier ────────────────────────────────────────────────────


class TestNpmVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.npm.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"username": "npmuser"}).encode(),
        )
        v = get_verifier("npm_token")
        assert v is not None
        result = v.probe("npm_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "npmuser" in (result.identity or "")


# ── Slack verifier ───────────────────────────────────────────────────


class TestSlackVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.slack.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({
                "ok": True, "user": "bot", "team": "myteam",
            }).encode(),
        )
        v = get_verifier("slack_token")
        assert v is not None
        result = v.probe("xoxb-fake")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.slack.http_probe",
    )
    def test_invalid_auth(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"ok": False, "error": "invalid_auth"}).encode(),
        )
        v = get_verifier("slack_token")
        assert v is not None
        result = v.probe("xoxb-fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# ── SaaS API key verifiers ──────────────────────────────────────────


class TestSaaSVerifiers:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.saas_api_keys.http_probe",
    )
    def test_anthropic_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=200, body=b"{}")
        v = get_verifier("anthropic_api_key")
        assert v is not None
        result = v.probe("sk-ant-api03-fake")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.saas_api_keys.bearer_probe",
    )
    def test_openai_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("openai_api_key")
        assert v is not None
        result = v.probe("sk-proj-fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.saas_api_keys.http_probe",
    )
    def test_stripe_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=200, body=b"{}")
        v = get_verifier("stripe_secret")
        assert v is not None
        result = v.probe("sk_live_fake")
        assert result.outcome == VerifyOutcome.VERIFIED


# ── verify_token (top-level) ────────────────────────────────────────


class TestVerifyToken:
    def test_unknown_detector(self) -> None:
        result = verify_token("totally_made_up", "value")
        assert result.outcome == VerifyOutcome.UNKNOWN
        assert "no verifier" in result.reason

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_delegates_to_verifier(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"login": "x"}).encode(),
        )
        result = verify_token("github_token", "ghp_fake")
        assert result.outcome == VerifyOutcome.VERIFIED


# ── Scanner integration ─────────────────────────────────────────────


class TestScannerVerification:
    """Test the _verify_and_enrich_findings function."""

    def _make_finding(
        self, check_id: str, resource: str, passed: bool,
    ) -> Any:
        from pipeline_check.core.checks.base import (
            Finding,
            Severity,
        )
        return Finding(
            check_id=check_id,
            title="test",
            severity=Severity.CRITICAL,
            resource=resource,
            description="found: github_token:ghp_…90",
            recommendation="rotate",
            passed=passed,
        )

    def _make_context(self, path: str, doc: dict[str, Any]) -> Any:
        ctx = MagicMock()
        wf = MagicMock()
        wf.path = path
        wf.data = doc
        ctx.workflows = [wf]
        ctx.pipelines = []
        ctx.files = []
        return ctx

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_verified_promotes_to_critical(
        self, mock_probe: MagicMock,
    ) -> None:
        from pipeline_check.core.checks.base import Confidence, Severity
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"login": "octocat"}).encode(),
        )

        doc = {"env": {"GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}
        finding = self._make_finding("GHA-008", "wf.yml", passed=False)
        ctx = self._make_context("wf.yml", doc)

        _verify_and_enrich_findings([finding], ctx)

        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.HIGH
        assert finding.confidence_locked is True
        assert "VERIFIED ACTIVE" in finding.description

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_unverified_demotes_to_low(
        self, mock_probe: MagicMock,
    ) -> None:
        from pipeline_check.core.checks.base import Confidence, Severity
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        mock_probe.return_value = ProbeResponse(
            status=401, body=b"Bad credentials",
        )

        doc = {"env": {"GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}
        finding = self._make_finding("GHA-008", "wf.yml", passed=False)
        ctx = self._make_context("wf.yml", doc)

        _verify_and_enrich_findings([finding], ctx)

        assert finding.severity == Severity.LOW
        assert finding.confidence == Confidence.LOW
        assert "revoked or rotated" in finding.description

    def test_passed_finding_is_skipped(self) -> None:
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        finding = self._make_finding("GHA-008", "wf.yml", passed=True)
        ctx = self._make_context("wf.yml", {"env": {"GH": "ghp_abc"}})

        _verify_and_enrich_findings([finding], ctx)
        assert "VERIFIED" not in finding.description

    def test_non_secret_check_is_skipped(self) -> None:
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        finding = self._make_finding("GHA-001", "wf.yml", passed=False)
        ctx = self._make_context("wf.yml", {
            "env": {"GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
        })

        original_desc = finding.description
        _verify_and_enrich_findings([finding], ctx)
        assert finding.description == original_desc

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_show_identity_redacted_by_default(
        self, mock_probe: MagicMock,
    ) -> None:
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"login": "octocat"}).encode(),
        )

        doc = {"env": {"GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}
        finding = self._make_finding("GHA-008", "wf.yml", passed=False)
        ctx = self._make_context("wf.yml", doc)

        _verify_and_enrich_findings([finding], ctx, show_identity=False)
        # Full "octocat" should not appear, only redacted form.
        assert "octocat" not in finding.description
        assert "gith***at" in finding.description

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers.github.bearer_probe",
    )
    def test_show_identity_full_when_opted_in(
        self, mock_probe: MagicMock,
    ) -> None:
        from pipeline_check.core.scanner import _verify_and_enrich_findings

        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"login": "octocat"}).encode(),
        )

        doc = {"env": {"GH": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}
        finding = self._make_finding("GHA-008", "wf.yml", passed=False)
        ctx = self._make_context("wf.yml", doc)

        _verify_and_enrich_findings([finding], ctx, show_identity=True)
        assert "octocat" in finding.description


# ── Docker Hub verifier ────────────────────────────────────────────


class TestDockerHubVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".docker_hub.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"username": "myuser"}).encode(),
        )
        v = get_verifier("docker_hub_pat")
        assert v is not None
        result = v.probe("dckr_pat_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "myuser" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".docker_hub.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("docker_hub_pat")
        assert v is not None
        result = v.probe("dckr_pat_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".docker_hub.bearer_probe",
    )
    def test_unknown_on_server_error(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=500, body=b"")
        v = get_verifier("docker_hub_pat")
        assert v is not None
        result = v.probe("dckr_pat_fake")
        assert result.outcome == VerifyOutcome.UNKNOWN


# ── PyPI verifier ──────────────────────────────────────────────────


class TestPyPIVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".pypi.bearer_probe",
    )
    def test_verified_via_405(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=405, body=b"")
        v = get_verifier("pypi_token")
        assert v is not None
        result = v.probe("pypi-AgEIcHlwaS5vcmcfake")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".pypi.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=403, body=b"")
        v = get_verifier("pypi_token")
        assert v is not None
        result = v.probe("pypi-AgEIcHlwaS5vcmcfake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# ── Google API key verifier ────────────────────────────────────────


class TestGoogleAPIKeyVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".google.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"models": []}).encode(),
        )
        v = get_verifier("google_api_key")
        assert v is not None
        result = v.probe("AIzaSyFake35CharacterKeyHereXX")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".google.http_probe",
    )
    def test_unverified_invalid_key(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=403,
            body=json.dumps({
                "error": {"status": "PERMISSION_DENIED",
                          "message": "API_KEY_INVALID"},
            }).encode(),
        )
        v = get_verifier("google_api_key")
        assert v is not None
        result = v.probe("AIzaSyFake35CharacterKeyHereXX")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".google.http_probe",
    )
    def test_unknown_on_server_error(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=500, body=b"")
        v = get_verifier("google_api_key")
        assert v is not None
        result = v.probe("AIzaSyFake35CharacterKeyHereXX")
        assert result.outcome == VerifyOutcome.UNKNOWN


# ── JWT verifier ───────────────────────────────────────────────────


class TestJWTVerifier:
    @staticmethod
    def _make_jwt(payload: dict) -> str:
        import base64 as b64
        header = b64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode(),
        ).rstrip(b"=").decode()
        body = b64.urlsafe_b64encode(
            json.dumps(payload).encode(),
        ).rstrip(b"=").decode()
        return f"{header}.{body}.fakesignature"

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".jwt.bearer_probe",
    )
    def test_verified_auth0(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"sub": "auth0|12345"}).encode(),
        )
        token = self._make_jwt({
            "iss": "https://myapp.auth0.com/",
            "sub": "auth0|12345",
        })
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe(token)
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "auth0" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".jwt.bearer_probe",
    )
    def test_unverified_expired(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        token = self._make_jwt({
            "iss": "https://myapp.auth0.com/",
            "sub": "auth0|12345",
        })
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe(token)
        assert result.outcome == VerifyOutcome.UNVERIFIED

    def test_unknown_for_github_oidc(self) -> None:
        token = self._make_jwt({
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:org/repo:ref:refs/heads/main",
        })
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe(token)
        assert result.outcome == VerifyOutcome.UNKNOWN
        assert "github-oidc" in (result.identity or "")

    def test_unknown_for_unrecognized_issuer(self) -> None:
        token = self._make_jwt({
            "iss": "https://custom-idp.example.com",
            "sub": "user123",
        })
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe(token)
        assert result.outcome == VerifyOutcome.UNKNOWN
        assert "custom-idp" in (result.reason or "")

    def test_unknown_for_missing_issuer(self) -> None:
        token = self._make_jwt({"sub": "user123"})
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe(token)
        assert result.outcome == VerifyOutcome.UNKNOWN
        assert "missing" in (result.reason or "").lower()

    def test_unknown_for_invalid_jwt(self) -> None:
        v = get_verifier("jwt")
        assert v is not None
        result = v.probe("not.a.valid-jwt")
        assert result.outcome == VerifyOutcome.UNKNOWN


# -- DigitalOcean verifier -----------------------------------------------


class TestDigitalOceanVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps(
                {"account": {"email": "user@example.com"}},
            ).encode(),
        )
        v = get_verifier("digitalocean_token")
        assert v is not None
        result = v.probe("dop_v1_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "user@example.com" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("digitalocean_token")
        assert v is not None
        result = v.probe("dop_v1_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.bearer_probe",
    )
    def test_unknown_on_server_error(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=500, body=b"")
        v = get_verifier("digitalocean_token")
        assert v is not None
        result = v.probe("dop_v1_fake")
        assert result.outcome == VerifyOutcome.UNKNOWN


# -- Netlify verifier ----------------------------------------------------


class TestNetlifyVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"email": "dev@example.com"}).encode(),
        )
        v = get_verifier("netlify_token")
        assert v is not None
        result = v.probe("nfp_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "dev@example.com" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("netlify_token")
        assert v is not None
        result = v.probe("nfp_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Terraform Cloud verifier -------------------------------------------


class TestTerraformCloudVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({
                "data": {"attributes": {"username": "terraform-user"}},
            }).encode(),
        )
        v = get_verifier("terraform_cloud_token")
        assert v is not None
        result = v.probe("fake.atlasv1.faketoken")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "terraform-user" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".cloud_deploy_keys.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("terraform_cloud_token")
        assert v is not None
        result = v.probe("fake.atlasv1.faketoken")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Linear verifier -----------------------------------------------------


class TestLinearVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({
                "data": {"viewer": {"name": "Jane", "email": "j@co.com"}},
            }).encode(),
        )
        v = get_verifier("linear_api_key")
        assert v is not None
        result = v.probe("lin_api_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "Jane" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("linear_api_key")
        assert v is not None
        result = v.probe("lin_api_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Atlassian verifier --------------------------------------------------


class TestAtlassianVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"name": "Jira Admin"}).encode(),
        )
        v = get_verifier("atlassian_api_token")
        assert v is not None
        result = v.probe("ATATT3fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "Jira Admin" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("atlassian_api_token")
        assert v is not None
        result = v.probe("ATATT3fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Asana verifier ------------------------------------------------------


class TestAsanaVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"data": {"name": "Dev User"}}).encode(),
        )
        v = get_verifier("asana_pat")
        assert v is not None
        result = v.probe("0/0000000000000000:fake_not_a_real_asana_token_")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "Dev User" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("asana_pat")
        assert v is not None
        result = v.probe("0/0000000000000000:fake_not_a_real_asana_token_")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- New Relic verifier --------------------------------------------------


class TestNewRelicVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({
                "data": {
                    "actor": {
                        "user": {"name": "SRE", "email": "sre@co.com"},
                    },
                },
            }).encode(),
        )
        v = get_verifier("new_relic_api_key")
        assert v is not None
        result = v.probe("NRAK-fakefakefakefakefakefak")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "SRE" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".devtools_keys.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=403, body=b"")
        v = get_verifier("new_relic_api_key")
        assert v is not None
        result = v.probe("NRAK-fakefakefakefakefakefak")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Telegram Bot verifier -----------------------------------------------


class TestTelegramBotVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".telegram.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({
                "ok": True,
                "result": {"username": "my_bot", "id": 123456789},
            }).encode(),
        )
        v = get_verifier("telegram_bot_token")
        assert v is not None
        result = v.probe("123456789:ABCdefGHIjklMNOpqrSTUvwxyz12345678_")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "my_bot" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".telegram.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("telegram_bot_token")
        assert v is not None
        result = v.probe("123456789:ABCdefGHIjklMNOpqrSTUvwxyz12345678_")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".telegram.http_probe",
    )
    def test_unknown_on_server_error(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=500, body=b"")
        v = get_verifier("telegram_bot_token")
        assert v is not None
        result = v.probe("123456789:ABCdefGHIjklMNOpqrSTUvwxyz12345678_")
        assert result.outcome == VerifyOutcome.UNKNOWN


# -- Replicate verifier --------------------------------------------------


class TestReplicateVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"username": "mluser"}).encode(),
        )
        v = get_verifier("replicate_token")
        assert v is not None
        result = v.probe("r8_fake")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "mluser" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("replicate_token")
        assert v is not None
        result = v.probe("r8_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Cohere verifier -----------------------------------------------------


class TestCohereVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=200, body=b"{}")
        v = get_verifier("cohere_api_key")
        assert v is not None
        result = v.probe("co_pat_fake")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("cohere_api_key")
        assert v is not None
        result = v.probe("co_pat_fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED


# -- Mailchimp verifier --------------------------------------------------


class TestMailchimpVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.http_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(
            status=200,
            body=json.dumps({"account_name": "MyCompany"}).encode(),
        )
        v = get_verifier("mailchimp_api_key")
        assert v is not None
        result = v.probe("xxxxxxxxxxtestxxxxxxxxxxxxxxxxxx-us6")
        assert result.outcome == VerifyOutcome.VERIFIED
        assert "MyCompany" in (result.identity or "")

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.http_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("mailchimp_api_key")
        assert v is not None
        result = v.probe("xxxxxxxxxxtestxxxxxxxxxxxxxxxxxx-us6")
        assert result.outcome == VerifyOutcome.UNVERIFIED

    def test_unknown_without_datacenter(self) -> None:
        v = get_verifier("mailchimp_api_key")
        assert v is not None
        result = v.probe("no_datacenter_suffix_here")
        assert result.outcome == VerifyOutcome.UNKNOWN
        assert "datacenter" in result.reason


# -- Square verifier -----------------------------------------------------


class TestSquareVerifier:
    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.bearer_probe",
    )
    def test_verified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=200, body=b"{}")
        v = get_verifier("square_access_token")
        assert v is not None
        result = v.probe("sq0atp-fake")
        assert result.outcome == VerifyOutcome.VERIFIED

    @patch(
        "pipeline_check.core.checks._primitives.secret_verifiers"
        ".more_saas_keys.bearer_probe",
    )
    def test_unverified(self, mock_probe: MagicMock) -> None:
        mock_probe.return_value = ProbeResponse(status=401, body=b"")
        v = get_verifier("square_access_token")
        assert v is not None
        result = v.probe("sq0atp-fake")
        assert result.outcome == VerifyOutcome.UNVERIFIED
