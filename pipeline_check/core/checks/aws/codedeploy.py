"""CodeDeploy security checks.

CD-001  Auto rollback on failure disabled                MEDIUM  CICD-SEC-1
CD-002  AllAtOnce deployment config (no canary/rolling)  HIGH    CICD-SEC-1
CD-003  No CloudWatch alarm monitoring on deployment     MEDIUM  CICD-SEC-10
"""

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity

# Deployment configs that deploy to all targets simultaneously with no traffic shifting.
_ALL_AT_ONCE_CONFIGS = {
    "CodeDeployDefault.AllAtOnce",
    "CodeDeployDefault.LambdaAllAtOnce",
    "CodeDeployDefault.ECSAllAtOnce",
}


class CodeDeployChecks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        client = self.session.client("codedeploy")

        try:
            app_names = self._list_applications(client)
        except ClientError as exc:
            return [Finding(
                check_id="CD-000",
                title="CodeDeploy API access failed",
                severity=Severity.INFO,
                resource="codedeploy",
                description=f"Could not list CodeDeploy applications: {exc}. CD checks skipped.",
                recommendation=(
                    "Ensure the IAM principal has codedeploy:ListApplications and "
                    "codedeploy:ListDeploymentGroups permissions."
                ),
                passed=False,
            )]

        findings: list[Finding] = []
        for app_name in app_names:
            try:
                groups = self._list_deployment_groups(client, app_name)
            except ClientError:
                continue
            if not groups:
                continue
            try:
                resp = client.batch_get_deployment_groups(
                    applicationName=app_name,
                    deploymentGroupNames=groups,
                )
            except ClientError:
                continue
            for group in resp.get("deploymentGroupsInfo", []):
                resource = f"{app_name}/{group['deploymentGroupName']}"
                findings.extend(self._check_group(group, resource))

        return findings

    @staticmethod
    def _list_applications(client) -> list[str]:
        names: list[str] = []
        paginator = client.get_paginator("list_applications")
        for page in paginator.paginate():
            names.extend(page.get("applications", []))
        return names

    @staticmethod
    def _list_deployment_groups(client, app_name: str) -> list[str]:
        names: list[str] = []
        paginator = client.get_paginator("list_deployment_groups")
        for page in paginator.paginate(applicationName=app_name):
            names.extend(page.get("deploymentGroups", []))
        return names

    def _check_group(self, group: dict, resource: str) -> list[Finding]:
        return [
            self._cd001_auto_rollback(group, resource),
            self._cd002_all_at_once(group, resource),
            self._cd003_alarm_config(group, resource),
        ]

    @staticmethod
    def _cd001_auto_rollback(group: dict, resource: str) -> Finding:
        rollback = group.get("autoRollbackConfiguration", {})
        enabled = rollback.get("enabled", False)
        events = rollback.get("events", [])
        # Useful rollback event: DEPLOYMENT_FAILURE
        has_failure_rollback = enabled and "DEPLOYMENT_FAILURE" in events

        if has_failure_rollback:
            desc = "Automatic rollback on deployment failure is enabled."
        else:
            desc = (
                "Automatic rollback on deployment failure is not configured. "
                "A failed deployment will leave the environment in an inconsistent "
                "or broken state until manually remediated."
            )

        return Finding(
            check_id="CD-001",
            title="Automatic rollback on failure not enabled",
            severity=Severity.MEDIUM,
            resource=resource,
            description=desc,
            recommendation=(
                "Enable autoRollbackConfiguration with at least the "
                "DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to "
                "the last successful revision when a deployment fails."
            ),
            passed=has_failure_rollback,
        )

    @staticmethod
    def _cd002_all_at_once(group: dict, resource: str) -> Finding:
        config_name: str = group.get("deploymentConfigName", "")
        is_all_at_once = config_name in _ALL_AT_ONCE_CONFIGS

        if not is_all_at_once:
            desc = f"Deployment uses a graduated config ({config_name!r})."
        else:
            desc = (
                f"Deployment is configured with '{config_name}', which routes all "
                f"traffic to the new revision simultaneously. A defective build "
                f"immediately impacts 100% of traffic with no canary validation window."
            )

        return Finding(
            check_id="CD-002",
            title="AllAtOnce deployment config — no canary or rolling strategy",
            severity=Severity.HIGH,
            resource=resource,
            description=desc,
            recommendation=(
                "Switch to a canary or linear deployment configuration "
                "(e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom "
                "rolling config) so that defects are caught before they affect all "
                "instances or traffic."
            ),
            passed=not is_all_at_once,
        )

    @staticmethod
    def _cd003_alarm_config(group: dict, resource: str) -> Finding:
        alarm_cfg = group.get("alarmConfiguration", {})
        enabled = alarm_cfg.get("enabled", False)
        alarms = alarm_cfg.get("alarms", [])
        passed = enabled and len(alarms) > 0

        if passed:
            names = [a["name"] for a in alarms]
            desc = f"CloudWatch alarm monitoring is enabled: {names}."
        else:
            desc = (
                "No CloudWatch alarms are configured for this deployment group. "
                "Without alarm-based monitoring, error spikes or latency regressions "
                "introduced by a deployment will not automatically halt or roll back "
                "the release."
            )

        return Finding(
            check_id="CD-003",
            title="No CloudWatch alarm monitoring on deployment group",
            severity=Severity.MEDIUM,
            resource=resource,
            description=desc,
            recommendation=(
                "Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) "
                "to the deployment group's alarmConfiguration. Enable automatic "
                "rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments."
            ),
            passed=passed,
        )
