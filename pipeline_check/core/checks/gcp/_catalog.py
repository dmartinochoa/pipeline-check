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
                    "default_kms_key_name": getattr(
                        b, "default_kms_key_name", None,
                    ),
                    "logging": (
                        {
                            "log_bucket": b.logging.get("logBucket", ""),
                            "log_object_prefix": b.logging.get(
                                "logObjectPrefix", "",
                            ),
                        }
                        if isinstance(b.logging, dict) and b.logging
                        else (
                            {
                                "log_bucket": getattr(
                                    b.logging, "log_bucket", "",
                                ),
                                "log_object_prefix": getattr(
                                    b.logging, "log_object_prefix", "",
                                ),
                            }
                            if b.logging
                            else None
                        )
                    ),
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


    # ------------------------------------------------------------------
    # Compute Engine
    # ------------------------------------------------------------------

    def compute_instances(self) -> list[dict[str, Any]]:
        """Return all Compute Engine instances in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.compute_v1 import InstancesClient

            client = InstancesClient(credentials=self.session.credentials)
            instances: list[dict[str, Any]] = []
            for zone, scoped_list in client.aggregated_list(
                request={"project": self.session.project_id},
            ):
                for inst in (scoped_list.instances or []):
                    instances.append({
                        "name": inst.name,
                        "zone": zone,
                        "status": inst.status,
                        "service_accounts": [
                            sa.email
                            for sa in (inst.service_accounts or [])
                        ],
                        "shielded_instance_config": (
                            {
                                "enable_vtpm": inst.shielded_instance_config.enable_vtpm,
                                "enable_integrity_monitoring": (
                                    inst.shielded_instance_config.enable_integrity_monitoring
                                ),
                            }
                            if inst.shielded_instance_config
                            else None
                        ),
                        "metadata": {
                            item.key: item.value
                            for item in (
                                inst.metadata.items or []
                                if inst.metadata
                                else []
                            )
                        },
                        "network_interfaces": [
                            {
                                "name": ni.name,
                                "network": ni.network,
                                "access_configs": [
                                    {
                                        "name": ac.name,
                                        "nat_ip": ac.nat_i_p,
                                        "type": ac.type_,
                                    }
                                    for ac in (ni.access_configs or [])
                                ],
                            }
                            for ni in (inst.network_interfaces or [])
                        ],
                        "scheduling": (
                            {
                                "automatic_restart": inst.scheduling.automatic_restart,
                            }
                            if inst.scheduling
                            else None
                        ),
                    })
            return instances
        return self._memo("compute:instances", _load)

    def compute_firewalls(self) -> list[dict[str, Any]]:
        """Return all VPC firewall rules in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.compute_v1 import FirewallsClient

            client = FirewallsClient(credentials=self.session.credentials)
            return [
                {
                    "name": fw.name,
                    "direction": fw.direction,
                    "allowed": [
                        {
                            "protocol": a.I_p_protocol,
                            "ports": list(a.ports) if a.ports else [],
                        }
                        for a in (fw.allowed or [])
                    ],
                    "source_ranges": list(fw.source_ranges or []),
                    "target_tags": list(fw.target_tags or []),
                    "disabled": fw.disabled,
                    "log_config": (
                        {"enable": fw.log_config.enable}
                        if fw.log_config
                        else {"enable": False}
                    ),
                }
                for fw in client.list(
                    request={"project": self.session.project_id},
                )
            ]
        return self._memo("network:firewalls", _load)

    def compute_networks(self) -> list[dict[str, Any]]:
        """Return all VPC networks in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.compute_v1 import NetworksClient

            client = NetworksClient(credentials=self.session.credentials)
            return [
                {
                    "name": nw.name,
                    "auto_create_subnetworks": nw.auto_create_subnetworks,
                    "description": nw.description,
                }
                for nw in client.list(
                    request={"project": self.session.project_id},
                )
            ]
        return self._memo("network:networks", _load)

    def compute_subnetworks(self) -> list[dict[str, Any]]:
        """Return all VPC subnetworks in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.compute_v1 import SubnetworksClient

            client = SubnetworksClient(
                credentials=self.session.credentials,
            )
            subnets: list[dict[str, Any]] = []
            for region, scoped_list in client.aggregated_list(
                request={"project": self.session.project_id},
            ):
                for sub in (scoped_list.subnetworks or []):
                    subnets.append({
                        "name": sub.name,
                        "region": region,
                        "private_ip_google_access": (
                            sub.private_ip_google_access
                        ),
                        "log_config": (
                            {"enable": sub.log_config.enable}
                            if sub.log_config
                            else {"enable": False}
                        ),
                    })
            return subnets
        return self._memo("network:subnetworks", _load)

    def compute_routers(self) -> list[dict[str, Any]]:
        """Return all Cloud Routers in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.compute_v1 import RoutersClient

            client = RoutersClient(credentials=self.session.credentials)
            routers: list[dict[str, Any]] = []
            for region, scoped_list in client.aggregated_list(
                request={"project": self.session.project_id},
            ):
                for r in (scoped_list.routers or []):
                    routers.append({
                        "name": r.name,
                        "region": region,
                        "nats": [
                            {"name": n.name}
                            for n in (r.nats or [])
                        ],
                    })
            return routers
        return self._memo("network:routers", _load)

    # ------------------------------------------------------------------
    # Cloud Logging (extended)
    # ------------------------------------------------------------------

    def log_metrics(self) -> list[dict[str, Any]]:
        """Return all log-based metrics in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import logging_v2

            client = logging_v2.MetricsServiceV2Client(
                credentials=self.session.credentials,
            )
            parent = f"projects/{self.session.project_id}"
            return [
                {
                    "name": m.name,
                    "filter": m.filter_,
                    "description": m.description,
                }
                for m in client.list_log_metrics(
                    request={"parent": parent},
                )
            ]
        return self._memo("logging:metrics", _load)

    # ------------------------------------------------------------------
    # IAM (extended)
    # ------------------------------------------------------------------

    def org_policies(self) -> list[dict[str, Any]]:
        """Return organization policies set on the project."""
        def _load() -> list[dict[str, Any]]:
            import google.auth
            import google.auth.transport.requests
            import requests as http_requests

            creds = self.session.credentials
            if not creds.valid:
                creds.refresh(google.auth.transport.requests.Request())

            url = (
                "https://orgpolicy.googleapis.com/v2/"
                f"projects/{self.session.project_id}/policies"
            )
            headers = {"Authorization": f"Bearer {creds.token}"}
            resp = http_requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return [
                {
                    "name": p.get("name", ""),
                    "spec": p.get("spec", {}),
                }
                for p in data.get("policies", [])
            ]
        return self._memo("iam:org_policies", _load)

    # ------------------------------------------------------------------
    # Cloud SQL
    # ------------------------------------------------------------------

    def cloud_sql_instances(self) -> list[dict[str, Any]]:
        """Return all Cloud SQL instances in the project."""
        def _load() -> list[dict[str, Any]]:
            import google.auth
            import google.auth.transport.requests
            import requests as http_requests

            creds = self.session.credentials
            if not creds.valid:
                creds.refresh(google.auth.transport.requests.Request())

            url = (
                "https://sqladmin.googleapis.com/v1/projects/"
                f"{self.session.project_id}/instances"
            )
            headers = {"Authorization": f"Bearer {creds.token}"}
            resp = http_requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            instances: list[dict[str, Any]] = []
            for item in data.get("items", []):
                settings = item.get("settings", {})
                instances.append({
                    "name": item.get("name", ""),
                    "settings": {
                        "ipConfiguration": settings.get(
                            "ipConfiguration", {},
                        ),
                        "backupConfiguration": settings.get(
                            "backupConfiguration", {},
                        ),
                        "databaseFlags": settings.get(
                            "databaseFlags", [],
                        ),
                    },
                    "instanceType": item.get("instanceType", ""),
                    "state": item.get("state", ""),
                })
            return instances
        return self._memo("cloudsql:instances", _load)

    # ------------------------------------------------------------------
    # Cloud Run / Functions
    # ------------------------------------------------------------------

    def cloud_run_services(self) -> list[dict[str, Any]]:
        """Return all Cloud Run services in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.run_v2 import ServicesClient

            client = ServicesClient(credentials=self.session.credentials)
            parent = f"projects/{self.session.project_id}/locations/-"
            return [
                {
                    "name": svc.name,
                    "template": {
                        "service_account": (
                            svc.template.service_account
                            if svc.template
                            else ""
                        ),
                        "vpc_access": (
                            {
                                "connector": (
                                    svc.template.vpc_access.connector
                                    if svc.template.vpc_access
                                    else ""
                                ),
                            }
                            if svc.template
                            else {}
                        ),
                        "scaling": (
                            {
                                "min_instance_count": (
                                    svc.template.scaling.min_instance_count
                                    if svc.template.scaling
                                    else 0
                                ),
                            }
                            if svc.template
                            else {"min_instance_count": 0}
                        ),
                    },
                    "ingress": (
                        svc.ingress.name if svc.ingress else "INGRESS_TRAFFIC_ALL"
                    ),
                }
                for svc in client.list_services(
                    request={"parent": parent},
                )
            ]
        return self._memo("cloudrun:services", _load)

    def cloud_functions(self) -> list[dict[str, Any]]:
        """Return all Cloud Functions (2nd gen) in the project."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud.functions_v2 import FunctionServiceClient

            client = FunctionServiceClient(
                credentials=self.session.credentials,
            )
            parent = f"projects/{self.session.project_id}/locations/-"
            return [
                {
                    "name": fn.name,
                    "service_config": {
                        "service_account_email": (
                            fn.service_config.service_account_email
                            if fn.service_config
                            else ""
                        ),
                        "vpc_connector": (
                            fn.service_config.vpc_connector
                            if fn.service_config
                            else ""
                        ),
                    },
                }
                for fn in client.list_functions(
                    request={"parent": parent},
                )
            ]
        return self._memo("cloudrun:functions", _load)

    # ------------------------------------------------------------------
    # KMS (extended)
    # ------------------------------------------------------------------

    def kms_key_rings(self) -> list[dict[str, Any]]:
        """Return all KMS key rings with their IAM policies."""
        def _load() -> list[dict[str, Any]]:
            from google.cloud import kms

            client = kms.KeyManagementServiceClient(
                credentials=self.session.credentials,
            )
            project = self.session.project_id
            rings: list[dict[str, Any]] = []
            for location in ("global", "us", "europe", "asia"):
                parent = f"projects/{project}/locations/{location}"
                try:
                    for ring in client.list_key_rings(
                        request={"parent": parent},
                    ):
                        try:
                            policy = client.get_iam_policy(
                                request={"resource": ring.name},
                            )
                            bindings = [
                                {
                                    "role": b.role,
                                    "members": list(b.members),
                                }
                                for b in (policy.bindings or [])
                            ]
                        except Exception:
                            bindings = []
                        rings.append({
                            "name": ring.name,
                            "iam_policy": bindings,
                        })
                except Exception:
                    pass
            return rings
        return self._memo("kms:key_rings", _load)


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
