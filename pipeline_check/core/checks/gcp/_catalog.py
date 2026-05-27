"""Shared GCP resource catalog.

Every rule under ``pipeline_check.core.checks.gcp.rules`` receives a
:class:`ResourceCatalog` rather than a bare session.  The catalog
enumerates each GCP resource type at most once per scan and caches
the result.

Each catalog method returns a (possibly empty) list on success.  On API
failure the error is recorded against a service tag so the orchestrator
can emit a single ``<PREFIX>-000`` degraded finding per service.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._session import GCPSession


class ResourceCatalog:
    """Lazy, caching facade over the GCP APIs."""

    def __init__(self, session: GCPSession) -> None:
        self.session = session
        self.errors: dict[str, str] = {}
        self._cache: dict[str, Any] = {}
        self._clients: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Cache primitive
    # ------------------------------------------------------------------

    def _memo(self, key: str, loader: Callable[[], Any]) -> Any:
        if key in self._cache:
            return self._cache[key]
        try:
            value = loader()
        except Exception as exc:
            svc = key.split(":", 1)[0]
            self.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
            value = []
        self._cache[key] = value
        return value

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------

    def project_iam_policy(self) -> dict[str, Any]:
        """Return the project-level IAM policy."""
        def _load() -> dict[str, Any]:
            from google.cloud import resourcemanager_v3

            client = resourcemanager_v3.ProjectsClient(
                credentials=self.session.credentials,
            )
            policy = client.get_iam_policy(
                request={"resource": f"projects/{self.session.project_id}"},
            )
            return {
                "bindings": [
                    {
                        "role": b.role,
                        "members": list(b.members),
                        "condition": (
                            {
                                "title": b.condition.title,
                                "expression": b.condition.expression,
                            }
                            if b.condition and b.condition.expression
                            else None
                        ),
                    }
                    for b in (policy.bindings or [])
                ],
                "audit_configs": [
                    {
                        "service": ac.service,
                        "audit_log_configs": [
                            {"log_type": lc.log_type}
                            for lc in (ac.audit_log_configs or [])
                        ],
                    }
                    for ac in (policy.audit_configs or [])
                ],
            }
        return self._memo("iam:project_policy", _load)

    def service_accounts(self) -> list[dict[str, Any]]:
        """Return all service accounts in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import iam_admin_v1

            client = iam_admin_v1.IAMClient(
                credentials=self.session.credentials,
            )
            accounts = client.list_service_accounts(
                request={
                    "name": f"projects/{self.session.project_id}",
                },
            )
            return [
                {
                    "email": sa.email,
                    "name": sa.name,
                    "display_name": sa.display_name,
                    "disabled": sa.disabled,
                }
                for sa in accounts
            ]
        return self._memo("iam:service_accounts", _load)

    def service_account_keys(self, sa_email: str) -> list[dict[str, Any]]:
        """Return keys for a specific service account."""
        cache_key = f"iam:sa_keys:{sa_email}"
        def _load() -> list[dict[str, Any]]:
            from google.cloud import iam_admin_v1

            client = iam_admin_v1.IAMClient(
                credentials=self.session.credentials,
            )
            keys = client.list_service_account_keys(
                request={
                    "name": f"projects/{self.session.project_id}"
                    f"/serviceAccounts/{sa_email}",
                },
            )
            return [
                {
                    "name": k.name,
                    "key_type": k.key_type.name if k.key_type else "UNKNOWN",
                    "valid_after": str(k.valid_after_time),
                    "valid_before": str(k.valid_before_time),
                }
                for k in (keys.keys or [])
            ]
        return self._memo(cache_key, _load)

    # ------------------------------------------------------------------
    # Cloud Storage
    # ------------------------------------------------------------------

    def storage_buckets(self) -> list[dict[str, Any]]:
        """Return all Cloud Storage buckets in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import storage

            client = storage.Client(
                credentials=self.session.credentials,
                project=self.session.project_id,
            )
            return [
                {
                    "name": b.name,
                    "location": b.location,
                    "storage_class": b.storage_class,
                    "versioning_enabled": bool(b.versioning_enabled),
                    "iam_configuration": {
                        "uniform_bucket_level_access": {
                            "enabled": bool(
                                b.iam_configuration.get(
                                    "uniformBucketLevelAccess", {},
                                ).get("enabled", False)
                                if isinstance(b.iam_configuration, dict)
                                else getattr(
                                    getattr(
                                        b.iam_configuration,
                                        "uniform_bucket_level_access",
                                        None,
                                    ),
                                    "enabled",
                                    False,
                                )
                            ),
                        },
                    },
                    "iam_policy": _bucket_iam_policy(b),
                }
                for b in client.list_buckets()
            ]
        return self._memo("storage:buckets", _load)

    # ------------------------------------------------------------------
    # Cloud KMS
    # ------------------------------------------------------------------

    def kms_keys(self) -> list[dict[str, Any]]:
        """Return all KMS crypto keys across all key rings in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import kms

            client = kms.KeyManagementServiceClient(
                credentials=self.session.credentials,
            )
            project = self.session.project_id
            keys: list[dict[str, Any]] = []
            for location in ("global", "us", "europe", "asia"):
                parent = f"projects/{project}/locations/{location}"
                try:
                    for ring in client.list_key_rings(
                        request={"parent": parent},
                    ):
                        for key in client.list_crypto_keys(
                            request={"parent": ring.name},
                        ):
                            rotation = key.rotation_period
                            keys.append({
                                "name": key.name,
                                "purpose": key.purpose.name,
                                "protection_level": (
                                    key.version_template.protection_level.name
                                    if key.version_template
                                    else "SOFTWARE"
                                ),
                                "rotation_period_days": (
                                    rotation.total_seconds() / 86400
                                    if rotation
                                    else None
                                ),
                                "primary_state": (
                                    key.primary.state.name
                                    if key.primary
                                    else None
                                ),
                            })
                except Exception:
                    pass
            return keys
        return self._memo("kms:keys", _load)

    # ------------------------------------------------------------------
    # Artifact Registry
    # ------------------------------------------------------------------

    def artifact_registry_repos(self) -> list[dict[str, Any]]:
        """Return all Artifact Registry repositories in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import artifactregistry_v1

            client = artifactregistry_v1.ArtifactRegistryClient(
                credentials=self.session.credentials,
            )
            repos: list[dict[str, Any]] = []
            parent = f"projects/{self.session.project_id}/locations/-"
            for repo in client.list_repositories(
                request={"parent": parent},
            ):
                repos.append({
                    "name": repo.name,
                    "format": repo.format_.name if repo.format_ else "UNKNOWN",
                    "mode": repo.mode.name if repo.mode else "STANDARD_REPOSITORY",
                    "cleanup_policies": dict(repo.cleanup_policies) if repo.cleanup_policies else {},
                    "vulnerability_scanning_config": (
                        {
                            "enablement_config": (
                                repo.vulnerability_scanning_config.enablement_config.name
                                if repo.vulnerability_scanning_config
                                and repo.vulnerability_scanning_config.enablement_config
                                else "INHERITED"
                            ),
                        }
                        if repo.vulnerability_scanning_config
                        else {"enablement_config": "INHERITED"}
                    ),
                })
            return repos
        return self._memo("artifactregistry:repos", _load)

    # ------------------------------------------------------------------
    # Cloud Logging
    # ------------------------------------------------------------------

    def log_sinks(self) -> list[dict[str, Any]]:
        """Return all log sinks in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import logging_v2

            client = logging_v2.ConfigServiceV2Client(
                credentials=self.session.credentials,
            )
            parent = f"projects/{self.session.project_id}"
            return [
                {
                    "name": s.name,
                    "destination": s.destination,
                    "filter": s.filter_,
                    "disabled": s.disabled,
                }
                for s in client.list_sinks(request={"parent": parent})
            ]
        return self._memo("logging:sinks", _load)

    def log_buckets(self) -> list[dict[str, Any]]:
        """Return all log buckets in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import logging_v2

            client = logging_v2.ConfigServiceV2Client(
                credentials=self.session.credentials,
            )
            parent = f"projects/{self.session.project_id}/locations/-"
            return [
                {
                    "name": b.name,
                    "retention_days": b.retention_days,
                    "locked": b.locked,
                    "lifecycle_state": b.lifecycle_state.name if b.lifecycle_state else "ACTIVE",
                }
                for b in client.list_buckets(request={"parent": parent})
            ]
        return self._memo("logging:buckets", _load)


def _bucket_iam_policy(bucket: Any) -> list[dict[str, Any]]:
    """Retrieve IAM policy for a bucket, returning empty on error."""
    try:
        policy = bucket.get_iam_policy()
        return [
            {"role": role, "members": list(members)}
            for role, members in (policy.bindings or {}).items()
            if members
        ]
    except Exception:
        return []
