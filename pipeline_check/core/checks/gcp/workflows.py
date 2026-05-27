"""GCP rule orchestrator, runs every rule under ``gcp/rules/``."""
from __future__ import annotations

from ..base import Finding, Severity
from ..rule import apply_rule_metadata, discover_rules
from ._catalog import ResourceCatalog
from ._session import GCPSession
from .base import GCPBaseCheck

_RULE_PREFIX_TO_SERVICE: dict[str, str] = {
    "GCIAM": "iam",
    "GCS": "storage",
    "GCKMS": "kms",
    "GAR": "artifactregistry",
    "GCLOG": "logging",
    "GCNET": "network",
    "GCCE": "compute",
    "GCSQL": "cloudsql",
    "GCRUN": "cloudrun",
}

_DEGRADED: dict[str, tuple[str, str, str]] = {
    "iam": (
        "GCIAM-000",
        "GCP IAM",
        "Ensure the service account has roles/iam.securityReviewer "
        "or equivalent for IAM policy reads.",
    ),
    "storage": (
        "GCS-000",
        "Cloud Storage",
        "Ensure the service account has storage.buckets.list and "
        "storage.buckets.getIamPolicy permissions.",
    ),
    "kms": (
        "GCKMS-000",
        "Cloud KMS",
        "Ensure the service account has cloudkms.keyRings.list and "
        "cloudkms.cryptoKeys.list permissions.",
    ),
    "artifactregistry": (
        "GAR-000",
        "Artifact Registry",
        "Ensure the service account has "
        "artifactregistry.repositories.list permission.",
    ),
    "logging": (
        "GCLOG-000",
        "Cloud Logging",
        "Ensure the service account has logging.sinks.list and "
        "logging.buckets.list permissions.",
    ),
    "network": (
        "GCNET-000",
        "GCP Networking",
        "Ensure the service account has compute.firewalls.list and "
        "compute.networks.list permissions.",
    ),
    "compute": (
        "GCCE-000",
        "Compute Engine",
        "Ensure the service account has compute.instances.list "
        "permission.",
    ),
    "cloudsql": (
        "GCSQL-000",
        "Cloud SQL",
        "Ensure the service account has cloudsql.instances.list "
        "permission.",
    ),
    "cloudrun": (
        "GCRUN-000",
        "Cloud Run / Functions",
        "Ensure the service account has run.services.list and "
        "cloudfunctions.functions.list permissions.",
    ),
}


class GCPRuleChecks(GCPBaseCheck):
    """Runs every rule under ``pipeline_check.core.checks.gcp.rules``."""

    def __init__(
        self, session: GCPSession, target: str | None = None,
    ) -> None:
        super().__init__(session, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.gcp.rules",
        )

    def run(self) -> list[Finding]:
        catalog = ResourceCatalog(self.session)
        pending: list[tuple[str, list[Finding]]] = []
        for rule, check_fn in self._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(
                    svc, f"{type(exc).__name__}: {exc}",
                )
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings: list[Finding] = []
        degraded_services = set(catalog.errors)
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded_services:
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            check_id, label, recommendation = meta
            findings.append(Finding(
                check_id=check_id,
                title=f"{label} API access failed",
                severity=Severity.INFO,
                resource=label,
                description=(
                    f"Could not enumerate {label} resources: {msg}. "
                    "Rules depending on this data were skipped."
                ),
                recommendation=recommendation,
                passed=False,
            ))
        return findings
