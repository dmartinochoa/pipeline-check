"""CB-001 against a synthetic `terraform show -json` document."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.codebuild import CodeBuildChecks


def _plan(resources: list[dict], child_modules: list[dict] | None = None) -> dict:
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": resources,
                "child_modules": child_modules or [],
            }
        },
    }


def _codebuild(name: str, env_vars: list[dict]) -> dict:
    return {
        "address": f"aws_codebuild_project.{name}",
        "mode": "managed",
        "type": "aws_codebuild_project",
        "name": name,
        "values": {
            "environment": [
                {
                    "image": "aws/codebuild/standard:7.0",
                    "environment_variable": env_vars,
                }
            ],
        },
    }


class TestCB001:
    def test_plaintext_secret_fails(self):
        plan = _plan([
            _codebuild("bad", [
                {"name": "API_TOKEN", "value": "x", "type": "PLAINTEXT"},
            ]),
        ])
        findings = CodeBuildChecks(TerraformContext(plan)).run()
        f = next(x for x in findings if x.check_id == "CB-001")
        assert not f.passed
        assert "API_TOKEN" in f.description
        assert f.resource == "aws_codebuild_project.bad"

    def test_secrets_manager_type_passes(self):
        plan = _plan([
            _codebuild("good", [
                {"name": "API_TOKEN", "value": "arn:...", "type": "SECRETS_MANAGER"},
            ]),
        ])
        findings = CodeBuildChecks(TerraformContext(plan)).run()
        f = next(x for x in findings if x.check_id == "CB-001")
        assert f.passed

    def test_non_secret_plaintext_name_passes(self):
        plan = _plan([
            _codebuild("good", [
                {"name": "BUILD_MODE", "value": "release", "type": "PLAINTEXT"},
            ]),
        ])
        findings = CodeBuildChecks(TerraformContext(plan)).run()
        f = next(x for x in findings if x.check_id == "CB-001")
        assert f.passed

    def test_missing_type_defaults_to_plaintext(self):
        plan = _plan([
            _codebuild("bad", [
                {"name": "DB_PASSWORD", "value": "x"},  # no "type"
            ]),
        ])
        findings = CodeBuildChecks(TerraformContext(plan)).run()
        f = next(x for x in findings if x.check_id == "CB-001")
        assert not f.passed

    def test_resource_in_child_module_is_scanned(self):
        child = {
            "address": "module.pipeline",
            "resources": [_codebuild("nested", [
                {"name": "GITHUB_TOKEN", "value": "x", "type": "PLAINTEXT"},
            ])],
        }
        plan = _plan([], child_modules=[child])
        findings = CodeBuildChecks(TerraformContext(plan)).run()
        cb001 = next(x for x in findings if x.check_id == "CB-001")
        assert not cb001.passed

    def test_no_codebuild_resources_returns_empty(self):
        plan = _plan([{
            "address": "aws_s3_bucket.x",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "x",
            "values": {},
        }])
        assert CodeBuildChecks(TerraformContext(plan)).run() == []


class TestProviderRegistration:
    def test_terraform_provider_registered(self):
        from pipeline_check.core import providers
        assert "terraform" in providers.available()

    def test_scanner_runs_through_provider(self, tmp_path):
        import json as _json
        plan = _plan([
            _codebuild("bad", [
                {"name": "API_TOKEN", "value": "x", "type": "PLAINTEXT"},
            ]),
        ])
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(_json.dumps(plan))

        from pipeline_check.core.scanner import Scanner
        scanner = Scanner(pipeline="terraform", tf_plan=str(plan_path))
        findings = scanner.run()
        assert any(f.check_id == "CB-001" and not f.passed for f in findings)
        # Standards enrichment still runs end-to-end.
        cb001 = next(f for f in findings if f.check_id == "CB-001")
        assert any(c.standard == "owasp_cicd_top_10" for c in cb001.controls)
