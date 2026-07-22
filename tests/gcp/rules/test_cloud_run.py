"""GCRUN-001..004 -- Cloud Run service checks."""
from __future__ import annotations

from pipeline_check.core.checks.gcp.rules import (
    gcrun001_unauthenticated,
    gcrun002_custom_sa,
    gcrun003_min_instances,
    gcrun004_vpc_connector,
)


def _run_service(
    name: str = "svc-1",
    *,
    ingress: str = "INGRESS_TRAFFIC_ALL",
    service_account: str = "",
    min_instance_count: int = 0,
    vpc_connector: str = "",
    iam_policy: list | None = None,
) -> dict:
    return {
        "name": name,
        "ingress": ingress,
        "iam_policy": iam_policy if iam_policy is not None else [],
        "template": {
            "service_account": service_account,
            "scaling": {"min_instance_count": min_instance_count},
            "vpc_access": {"connector": vpc_connector},
        },
    }


# -----------------------------------------------------------------------
# GCRUN-001: Unauthenticated access (IAM run.invoker for allUsers)
# -----------------------------------------------------------------------

class TestGCRUN001:
    def test_allusers_invoker_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(iam_policy=[
                {"role": "roles/run.invoker", "members": ["allUsers"]},
            ])],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCRUN-001"
        assert "allUsers" in findings[0].description

    def test_all_authenticated_users_invoker_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(iam_policy=[
                {"role": "roles/run.invoker",
                 "members": ["allAuthenticatedUsers"]},
            ])],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert findings[0].passed is False

    def test_named_invoker_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(iam_policy=[
                {"role": "roles/run.invoker",
                 "members": ["serviceAccount:caller@proj.iam.gserviceaccount.com"]},
            ])],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert findings[0].passed is True

    def test_ingress_all_but_iam_restricted_passes(self, make_catalog):
        # The false positive the old ingress-only check produced: a
        # default ingress=ALL service that still requires IAM auth.
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(ingress="INGRESS_TRAFFIC_ALL", iam_policy=[]),
            ],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert findings[0].passed is True

    def test_public_member_on_non_invoker_role_passes(self, make_catalog):
        # allUsers on a viewer role is not invoke access.
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(iam_policy=[
                {"role": "roles/run.viewer", "members": ["allUsers"]},
            ])],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert findings[0].passed is True

    def test_no_services_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudrun:services": []})
        assert gcrun001_unauthenticated.check(cat) == []


# -----------------------------------------------------------------------
# GCRUN-002: Default compute SA
# -----------------------------------------------------------------------

class TestGCRUN002:
    def test_default_sa_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(service_account="12345-compute@developer.gserviceaccount.com"),
            ],
            "cloudrun:functions": [],
        })
        findings = gcrun002_custom_sa.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCRUN-002"

    def test_empty_sa_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(service_account="")],
            "cloudrun:functions": [],
        })
        findings = gcrun002_custom_sa.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_custom_sa_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(service_account="my-sa@proj.iam.gserviceaccount.com"),
            ],
            "cloudrun:functions": [],
        })
        findings = gcrun002_custom_sa.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_function_default_sa_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [],
            "cloudrun:functions": [
                {"name": "fn-1", "service_config": {
                    "service_account_email": "12345-compute@developer.gserviceaccount.com",
                    "vpc_connector": "",
                }},
            ],
        })
        findings = gcrun002_custom_sa.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False

    def test_no_services_or_functions_returns_empty(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [],
            "cloudrun:functions": [],
        })
        assert gcrun002_custom_sa.check(cat) == []


# -----------------------------------------------------------------------
# GCRUN-003: Min instances zero
# -----------------------------------------------------------------------

class TestGCRUN003:
    def test_zero_min_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(min_instance_count=0)],
        })
        findings = gcrun003_min_instances.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCRUN-003"

    def test_nonzero_min_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(min_instance_count=1)],
        })
        findings = gcrun003_min_instances.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_services_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudrun:services": []})
        assert gcrun003_min_instances.check(cat) == []


# -----------------------------------------------------------------------
# GCRUN-004: VPC connector
# -----------------------------------------------------------------------

class TestGCRUN004:
    def test_no_connector_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(vpc_connector="")],
        })
        findings = gcrun004_vpc_connector.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCRUN-004"

    def test_connector_present_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(vpc_connector="projects/p/locations/us/connectors/c1"),
            ],
        })
        findings = gcrun004_vpc_connector.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_no_services_returns_empty(self, make_catalog):
        cat = make_catalog(**{"cloudrun:services": []})
        assert gcrun004_vpc_connector.check(cat) == []
