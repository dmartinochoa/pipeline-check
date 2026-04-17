"""Shared AWS resource catalog.

Every rule under ``pipeline_check.core.checks.aws.rules`` receives a
:class:`ResourceCatalog` rather than a bare ``boto3.Session``. The
catalog enumerates each AWS resource type at most once per scan and
caches the result, so running 20 CodeBuild rules doesn't trigger 20
``ListProjects`` calls.

Each catalog method returns a (possibly empty) list on success. On API
failure, the error is recorded against a service tag so the
orchestrator can emit a single ``<prefix>-000`` degraded finding per
service rather than every rule emitting its own copy.
"""
from __future__ import annotations

import json
from typing import Any

import boto3
from botocore.exceptions import ClientError

from .._iam_policy import CICD_SERVICE_PRINCIPALS
from .base import AWSBaseCheck


class ResourceCatalog:
    """Lazy, caching facade over the AWS APIs used by multiple rules.

    The catalog is constructed once per scan (inside the AWS rule
    orchestrator) and passed to every rule. Methods cache their
    results on first call; subsequent calls return the cached list.
    """

    def __init__(self, session: boto3.Session) -> None:
        self.session = session
        #: service-tag -> error message; surfaced as degraded findings
        #: by the orchestrator after all rules have run.
        self.errors: dict[str, str] = {}
        self._cache: dict[str, Any] = {}
        # Reuse the retry-configured client construction from the
        # existing base check so throttling is handled uniformly.
        self._client_host = _ClientHost(session)

    # ------------------------------------------------------------------
    # boto client access
    # ------------------------------------------------------------------

    def client(self, service_name: str) -> Any:
        return self._client_host.client(service_name)

    # ------------------------------------------------------------------
    # Cache primitive
    # ------------------------------------------------------------------

    def _memo(self, key: str, loader) -> Any:
        if key in self._cache:
            return self._cache[key]
        try:
            value = loader()
        except ClientError as exc:
            # Record a per-service error (key prefix before ':').
            svc = key.split(":", 1)[0]
            self.errors.setdefault(svc, str(exc))
            value = []
        except Exception as exc:  # noqa: BLE001
            # In restricted environments or tests where session.client()
            # rejects an unconfigured service (KeyError from a stubbed
            # side_effect), treat it the same as an API access failure:
            # record a degraded error and return an empty list rather
            # than crashing the scan.
            svc = key.split(":", 1)[0]
            self.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
            value = []
        self._cache[key] = value
        return value

    # ------------------------------------------------------------------
    # CodeBuild
    # ------------------------------------------------------------------

    def codebuild_projects(self) -> list[dict]:
        """Return every CodeBuild project in the region as a ``BatchGetProjects`` dict."""
        def _load() -> list[dict]:
            client = self.client("codebuild")
            names: list[str] = []
            for page in client.get_paginator("list_projects").paginate():
                names.extend(page.get("projects", []))
            if not names:
                return []
            out: list[dict] = []
            for i in range(0, len(names), 100):
                resp = client.batch_get_projects(names=names[i : i + 100])
                out.extend(resp.get("projects", []))
            return out
        return self._memo("codebuild:projects", _load)

    def codebuild_source_credentials(self) -> dict[str, set[str]]:
        """Return ``{serverType: {authType, ...}}`` for account-stored CodeBuild creds.

        One ``list_source_credentials`` call is enough for the whole
        account; memoize so CB-006 doesn't issue it once per project.
        ``AccessDeniedException`` returns an empty mapping rather than
        erroring the whole service — the rule can still pass on inline
        auth evaluation alone.
        """
        def _load() -> dict[str, set[str]]:
            client = self.client("codebuild")
            by_server: dict[str, set[str]] = {}
            try:
                resp = client.list_source_credentials()
            except ClientError:
                return by_server
            for cred in resp.get("sourceCredentialsInfos", []):
                server = cred.get("serverType", "")
                auth = cred.get("authType", "")
                if server and auth:
                    by_server.setdefault(server, set()).add(auth)
            return by_server
        return self._memo("codebuild:source_credentials", _load)

    # ------------------------------------------------------------------
    # CodeDeploy
    # ------------------------------------------------------------------

    def codedeploy_deployment_groups(self) -> list[dict]:
        """Every CodeDeploy deployment group, with ``_ApplicationName`` injected.

        Rules reference ``group["_ApplicationName"]`` to build a
        ``"app/group"`` resource label matching the legacy CD-xxx output.
        """
        def _load() -> list[dict]:
            client = self.client("codedeploy")
            apps: list[str] = []
            for page in client.get_paginator("list_applications").paginate():
                apps.extend(page.get("applications", []))
            out: list[dict] = []
            for app in apps:
                try:
                    group_names: list[str] = []
                    for page in client.get_paginator(
                        "list_deployment_groups",
                    ).paginate(applicationName=app):
                        group_names.extend(page.get("deploymentGroups", []))
                    if not group_names:
                        continue
                    resp = client.batch_get_deployment_groups(
                        applicationName=app, deploymentGroupNames=group_names,
                    )
                    for g in resp.get("deploymentGroupsInfo", []):
                        g["_ApplicationName"] = app
                        out.append(g)
                except ClientError:
                    continue
            return out
        return self._memo("codedeploy:deployment_groups", _load)

    # ------------------------------------------------------------------
    # ECR
    # ------------------------------------------------------------------

    def ecr_repositories(self) -> list[dict]:
        """Return every ECR repository (``describe_repositories`` detail dicts)."""
        def _load() -> list[dict]:
            client = self.client("ecr")
            out: list[dict] = []
            for page in client.get_paginator("describe_repositories").paginate():
                out.extend(page.get("repositories", []))
            return out
        return self._memo("ecr:repositories", _load)

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------

    def s3_artifact_buckets(self) -> list[str]:
        """Artifact bucket names discovered from every CodePipeline.

        Centralises the discovery logic that used to live in both
        ``providers/aws.py``'s inventory pass and the legacy ``S3Checks``
        module. ``CodePipeline`` inaccessibility is not fatal — S3 rules
        simply have no buckets to inspect.
        """
        def _load() -> list[str]:
            buckets: set[str] = set()
            for pipeline in self.codepipeline_pipelines():
                store = pipeline.get("artifactStore") or {}
                if store.get("type") == "S3" and store.get("location"):
                    buckets.add(store["location"])
                for entry in (pipeline.get("artifactStores") or {}).values():
                    if entry.get("type") == "S3" and entry.get("location"):
                        buckets.add(entry["location"])
            return sorted(buckets)
        return self._memo("s3:artifact_buckets", _load)

    # ------------------------------------------------------------------
    # IAM role policies (per-role; results cached per role_name)
    # ------------------------------------------------------------------

    def iam_role_policy_docs(
        self, role_name: str,
    ) -> tuple[list[tuple[str, dict]], str | None]:
        """Return ``(docs, error)`` for inline + customer-managed policies.

        ``docs`` is a list of ``(name_or_arn, parsed_document)`` pairs
        suitable for ``_iam_policy`` walkers. ``error`` is non-None when
        *either* inline or attached listing failed — rules surface it so
        IAM-002 / IAM-004 / IAM-006 can emit "cannot verify" rather than
        false-positive "clean".

        AWS-managed policies are excluded because IAM-001 already
        handles ``AdministratorAccess`` and walking every AWS-managed
        policy attached would produce noise without signal.
        """
        key = f"iam:role:{role_name}:policy_docs"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        client = self.client("iam")
        docs: list[tuple[str, dict]] = []
        error: str | None = None

        try:
            for pname in client.list_role_policies(
                RoleName=role_name,
            ).get("PolicyNames", []):
                try:
                    resp = client.get_role_policy(
                        RoleName=role_name, PolicyName=pname,
                    )
                    doc = resp.get("PolicyDocument", {})
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    docs.append((pname, doc or {}))
                except (ClientError, json.JSONDecodeError):
                    continue
        except ClientError as exc:
            error = f"Could not list inline role policies: {exc}"

        try:
            for attached in client.list_attached_role_policies(
                RoleName=role_name,
            ).get("AttachedPolicies", []):
                arn = attached["PolicyArn"]
                if arn.startswith("arn:aws:iam::aws:"):
                    continue
                try:
                    pol = client.get_policy(PolicyArn=arn)["Policy"]
                    version_id = pol["DefaultVersionId"]
                    ver = client.get_policy_version(
                        PolicyArn=arn, VersionId=version_id,
                    )
                    doc = ver["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    docs.append((arn, doc or {}))
                except (ClientError, KeyError, json.JSONDecodeError):
                    continue
        except ClientError as exc:
            if error is None:
                error = f"Could not list attached role policies: {exc}"

        result = (docs, error)
        self._cache[key] = result
        return result

    def iam_role_attached_arns(
        self, role_name: str,
    ) -> tuple[list[str], str | None]:
        """Attached-policy ARNs (both AWS- and customer-managed) for *role_name*."""
        key = f"iam:role:{role_name}:attached_arns"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        client = self.client("iam")
        try:
            resp = client.list_attached_role_policies(RoleName=role_name)
            arns = [p["PolicyArn"] for p in resp.get("AttachedPolicies", [])]
            result = (arns, None)
        except ClientError as exc:
            result = ([], f"Could not list attached policies: {exc}")
        self._cache[key] = result
        return result

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------

    def cloudtrail_trails(self) -> list[dict]:
        """Return every CloudTrail trail visible in the region (merged with status)."""
        def _load() -> list[dict]:
            client = self.client("cloudtrail")
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
            for trail in trails:
                try:
                    status = client.get_trail_status(Name=trail.get("TrailARN") or trail["Name"])
                    trail["_IsLogging"] = bool(status.get("IsLogging"))
                except ClientError:
                    trail["_IsLogging"] = False
            return trails
        return self._memo("cloudtrail:trails", _load)

    # ------------------------------------------------------------------
    # CloudWatch Logs
    # ------------------------------------------------------------------

    def log_groups(self, prefix: str) -> list[dict]:
        """Return CloudWatch log groups whose name starts with *prefix*."""
        def _load() -> list[dict]:
            client = self.client("logs")
            out: list[dict] = []
            paginator = client.get_paginator("describe_log_groups")
            for page in paginator.paginate(logGroupNamePrefix=prefix):
                out.extend(page.get("logGroups", []))
            return out
        return self._memo(f"logs:{prefix}", _load)

    # ------------------------------------------------------------------
    # Secrets Manager
    # ------------------------------------------------------------------

    def secrets(self) -> list[dict]:
        """Return every secret metadata dict in the region."""
        def _load() -> list[dict]:
            client = self.client("secretsmanager")
            out: list[dict] = []
            for page in client.get_paginator("list_secrets").paginate():
                out.extend(page.get("SecretList", []))
            return out
        return self._memo("secretsmanager:secrets", _load)

    def secret_resource_policy(self, secret_arn: str) -> dict | None:
        """Return the parsed resource policy for *secret_arn* or None if unset."""
        client = self.client("secretsmanager")
        try:
            resp = client.get_resource_policy(SecretId=secret_arn)
        except ClientError:
            return None
        raw = resp.get("ResourcePolicy")
        if not raw:
            return None
        try:
            return json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            return None

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------

    def iam_roles(self) -> list[dict]:
        """Return every IAM role in the account (raw list_roles output)."""
        def _load() -> list[dict]:
            client = self.client("iam")
            out: list[dict] = []
            for page in client.get_paginator("list_roles").paginate():
                out.extend(page.get("Roles", []))
            return out
        return self._memo("iam:roles", _load)

    def iam_users(self) -> list[dict]:
        """Return every IAM user in the account."""
        def _load() -> list[dict]:
            client = self.client("iam")
            out: list[dict] = []
            for page in client.get_paginator("list_users").paginate():
                out.extend(page.get("Users", []))
            return out
        return self._memo("iam:users", _load)

    def cicd_roles(self) -> list[dict]:
        """IAM roles whose trust policy allows a CI/CD service principal."""
        out: list[dict] = []
        for role in self.iam_roles():
            doc = role.get("AssumeRolePolicyDocument")
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except json.JSONDecodeError:
                    continue
            if not isinstance(doc, dict):
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                principal = (stmt or {}).get("Principal", {}) or {}
                services = principal.get("Service", [])
                if isinstance(services, str):
                    services = [services]
                if any(s in CICD_SERVICE_PRINCIPALS for s in services):
                    out.append(role)
                    break
        return out

    def access_keys(self, user_name: str) -> list[dict]:
        """Access-key metadata for *user_name*, including last-used date."""
        client = self.client("iam")
        try:
            resp = client.list_access_keys(UserName=user_name)
        except ClientError as exc:
            self.errors.setdefault("iam", str(exc))
            return []
        keys = resp.get("AccessKeyMetadata", [])
        for key in keys:
            try:
                last = client.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"],
                )
                key["_LastUsedDate"] = last.get("AccessKeyLastUsed", {}).get(
                    "LastUsedDate"
                )
            except ClientError:
                key["_LastUsedDate"] = None
        return keys

    # ------------------------------------------------------------------
    # CodeArtifact
    # ------------------------------------------------------------------

    def codeartifact_domains(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("codeartifact")
            out: list[dict] = []
            for page in client.get_paginator("list_domains").paginate():
                out.extend(page.get("domains", []))
            return out
        return self._memo("codeartifact:domains", _load)

    def codeartifact_repositories(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("codeartifact")
            out: list[dict] = []
            for page in client.get_paginator("list_repositories").paginate():
                out.extend(page.get("repositories", []))
            return out
        return self._memo("codeartifact:repositories", _load)

    # ------------------------------------------------------------------
    # CodeCommit
    # ------------------------------------------------------------------

    def codecommit_repositories(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("codecommit")
            out: list[dict] = []
            for page in client.get_paginator("list_repositories").paginate():
                out.extend(page.get("repositories", []))
            return out
        return self._memo("codecommit:repositories", _load)

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------

    def lambda_functions(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("lambda")
            out: list[dict] = []
            for page in client.get_paginator("list_functions").paginate():
                out.extend(page.get("Functions", []))
            return out
        return self._memo("lambda:functions", _load)

    # ------------------------------------------------------------------
    # KMS
    # ------------------------------------------------------------------

    def kms_keys(self) -> list[dict]:
        """Customer-managed KMS keys (AWS-managed keys are excluded)."""
        def _load() -> list[dict]:
            client = self.client("kms")
            out: list[dict] = []
            for page in client.get_paginator("list_keys").paginate():
                for k in page.get("Keys", []):
                    try:
                        meta = client.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    except ClientError:
                        continue
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    out.append(meta)
            return out
        return self._memo("kms:keys", _load)

    # ------------------------------------------------------------------
    # SSM Parameter Store
    # ------------------------------------------------------------------

    def ssm_parameters(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("ssm")
            out: list[dict] = []
            for page in client.get_paginator("describe_parameters").paginate():
                out.extend(page.get("Parameters", []))
            return out
        return self._memo("ssm:parameters", _load)

    # ------------------------------------------------------------------
    # ECR
    # ------------------------------------------------------------------

    def ecr_pull_through_cache_rules(self) -> list[dict]:
        # Swallow ClientError locally so a PTC API failure (LocalStack
        # lacks this endpoint, or AccessDenied in prod) only costs ECR-006
        # visibility — not the entire ECR rule family. Without this,
        # self._memo would taint catalog.errors["ecr"] and the orchestrator
        # would suppress ECR-001..005 in favour of a single ECR-000.
        def _load() -> list[dict]:
            client = self.client("ecr")
            try:
                return client.describe_pull_through_cache_rules().get(
                    "pullThroughCacheRules", []
                )
            except Exception:  # noqa: BLE001
                return []
        return self._memo("ecr:ptc", _load)

    # ------------------------------------------------------------------
    # EventBridge
    # ------------------------------------------------------------------

    def eventbridge_rules(self) -> list[dict]:
        def _load() -> list[dict]:
            client = self.client("events")
            out: list[dict] = []
            for page in client.get_paginator("list_rules").paginate():
                out.extend(page.get("Rules", []))
            return out
        return self._memo("events:rules", _load)

    def eventbridge_targets(self, rule_name: str) -> list[dict]:
        client = self.client("events")
        try:
            resp = client.list_targets_by_rule(Rule=rule_name)
        except ClientError as exc:
            self.errors.setdefault("events", str(exc))
            return []
        return resp.get("Targets", [])

    # ------------------------------------------------------------------
    # CodePipeline
    # ------------------------------------------------------------------

    def codepipeline_pipelines(self) -> list[dict]:
        """Return every pipeline as ``GetPipeline`` output (already detailed)."""
        def _load() -> list[dict]:
            client = self.client("codepipeline")
            out: list[dict] = []
            for page in client.get_paginator("list_pipelines").paginate():
                for summary in page.get("pipelines", []):
                    try:
                        detail = client.get_pipeline(name=summary["name"])
                        pipeline = detail.get("pipeline", {})
                        if pipeline:
                            out.append(pipeline)
                    except ClientError:
                        continue
            return out
        return self._memo("codepipeline:pipelines", _load)


class _ClientHost(AWSBaseCheck):
    """Minimal adapter so ResourceCatalog can reuse AWSBaseCheck.client().

    The catalog isn't itself a check — it's a helper — but it needs the
    same retry-configured, per-session cached client construction.
    """

    def __init__(self, session: boto3.Session) -> None:
        super().__init__(session, target=None)

    def run(self):  # pragma: no cover - never invoked
        return []
