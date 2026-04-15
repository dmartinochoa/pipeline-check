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


def _by(findings, cid):
    return next(f for f in findings if f.check_id == cid)


def _project_full(name, *, source=None, logs_config=None, build_timeout=60,
                  env_vars=None, privileged=False, image="aws/codebuild/standard:7.0"):
    vals = {
        "name": name,
        "build_timeout": build_timeout,
        "environment": [{
            "image": image,
            "privileged_mode": privileged,
            "environment_variable": env_vars or [],
        }],
    }
    if source is not None:
        vals["source"] = source
    if logs_config is not None:
        vals["logs_config"] = logs_config
    return {
        "address": f"aws_codebuild_project.{name}",
        "mode": "managed", "type": "aws_codebuild_project", "name": name,
        "values": vals,
    }


def _source_cred(server_type, auth_type):
    return {
        "address": f"aws_codebuild_source_credential.{server_type}",
        "mode": "managed", "type": "aws_codebuild_source_credential",
        "name": server_type,
        "values": {"server_type": server_type, "auth_type": auth_type},
    }


def _webhook(project_name, filter_groups=None):
    vals = {"project_name": project_name}
    if filter_groups is not None:
        vals["filter_group"] = filter_groups
    return {
        "address": f"aws_codebuild_webhook.{project_name}",
        "mode": "managed", "type": "aws_codebuild_webhook", "name": project_name,
        "values": vals,
    }


class TestCB001ValuePatterns:
    def test_aws_access_key_value_detected(self):
        plan = _plan([
            _codebuild("bad", [
                {"name": "HARMLESS_NAME", "value": "AKIA" + "A" * 16, "type": "PLAINTEXT"},
            ]),
        ])
        f = _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-001")
        assert not f.passed
        assert "credential-like values" in f.description

    def test_github_pat_value_detected(self):
        plan = _plan([
            _codebuild("bad", [
                {"name": "X", "value": "ghp_" + "a" * 40, "type": "PLAINTEXT"},
            ]),
        ])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-001").passed

    def test_jwt_value_detected(self):
        plan = _plan([
            _codebuild("bad", [
                {"name": "X", "value": "eyJabcdefghij.abcdefghij.abcdefghij", "type": "PLAINTEXT"},
            ]),
        ])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-001").passed


class TestCB006:
    def test_inline_oauth_auth_fails(self):
        src = [{"type": "GITHUB", "auth": [{"type": "OAUTH"}]}]
        plan = _plan([_project_full("p", source=src)])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-006").passed

    def test_side_resource_pat_fails(self):
        src = [{"type": "GITHUB"}]
        plan = _plan([
            _project_full("p", source=src),
            _source_cred("GITHUB", "PERSONAL_ACCESS_TOKEN"),
        ])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-006").passed

    def test_codeconnections_passes(self):
        src = [{"type": "GITHUB"}]
        plan = _plan([_project_full("p", source=src)])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-006").passed

    def test_non_external_source_passes(self):
        src = [{"type": "CODECOMMIT"}]
        plan = _plan([_project_full("p", source=src)])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-006").passed


class TestCB007:
    def test_no_webhook_passes(self):
        plan = _plan([_project_full("p")])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-007").passed

    def test_webhook_without_filter_group_fails(self):
        plan = _plan([_project_full("p"), _webhook("p")])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-007").passed

    def test_webhook_with_filter_group_passes(self):
        plan = _plan([
            _project_full("p"),
            _webhook("p", filter_groups=[{"filter": [{"type": "EVENT", "pattern": "PUSH"}]}]),
        ])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-007").passed


class TestCB003Default:
    def test_missing_logs_config_passes(self):
        # Terraform default: cloudwatch_logs ENABLED; missing block → pass.
        plan = _plan([_project_full("p")])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-003").passed

    def test_both_disabled_fails(self):
        plan = _plan([_project_full("p", logs_config=[{
            "cloudwatch_logs": [{"status": "DISABLED"}],
            "s3_logs": [{"status": "DISABLED"}],
        }])])
        assert not _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-003").passed

    def test_s3_only_passes(self):
        plan = _plan([_project_full("p", logs_config=[{
            "cloudwatch_logs": [{"status": "DISABLED"}],
            "s3_logs": [{"status": "ENABLED"}],
        }])])
        assert _by(CodeBuildChecks(TerraformContext(plan)).run(), "CB-003").passed


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
