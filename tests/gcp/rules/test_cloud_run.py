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
) -> dict:
    return {
        "name": name,
        "ingress": ingress,
        "template": {
            "service_account": service_account,
            "scaling": {"min_instance_count": min_instance_count},
            "vpc_access": {"connector": vpc_connector},
        },
    }


# -----------------------------------------------------------------------
# GCRUN-001: Unauthenticated access
# -----------------------------------------------------------------------

class TestGCRUN001:
    def test_all_ingress_fails(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [_run_service(ingress="INGRESS_TRAFFIC_ALL")],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is False
        assert findings[0].check_id == "GCRUN-001"

    def test_internal_only_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(ingress="INGRESS_TRAFFIC_INTERNAL_ONLY"),
            ],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert len(findings) == 1
        assert findings[0].passed is True

    def test_internal_lb_passes(self, make_catalog):
        cat = make_catalog(**{
            "cloudrun:services": [
                _run_service(ingress="INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
            ],
        })
        findings = gcrun001_unauthenticated.check(cat)
        assert len(findings) == 1
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
