"""XPC-002 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``. Tests here cover the
reachability-anchor logic that XPC-002 layers on top of the basic
cross-product (matching ``oci_image`` ResourceAnchors collapse the
file-pair fallback into a single confirmed chain keyed on the image
identity).
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc002_floating_tag_continuity as r,
)
from pipeline_check.core.checks.base import (
    Confidence,
    ResourceAnchor,
    Severity,
)

from ._chain_helpers import make_failing


class TestXPC002:
    def test_fires_on_combined_df_k8s_failures(self) -> None:
        findings = [
            make_failing("DF-001", "Dockerfile"),
            make_failing("K8S-001", "deploy.yaml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-002"
        assert c.severity == Severity.HIGH
        assert "Dockerfile" in c.resources
        assert "deploy.yaml" in c.resources
        assert "DF-001" in c.triggering_check_ids
        assert "K8S-001" in c.triggering_check_ids

    def test_emits_one_chain_per_pair(self) -> None:
        # Two Dockerfiles + three manifests -> six pairs.
        findings = [
            make_failing("DF-001", "api/Dockerfile"),
            make_failing("DF-001", "worker/Dockerfile"),
            make_failing("K8S-001", "k8s/api.yaml"),
            make_failing("K8S-001", "k8s/worker.yaml"),
            make_failing("K8S-001", "k8s/cron.yaml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_reachability_confirmed_when_image_anchor_matches(self) -> None:
        img = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/redis",
        )
        chains = r.match([
            make_failing(
                "DF-001", "Dockerfile", resource_anchors=(img,),
            ),
            make_failing(
                "K8S-001", "k8s/redis.yaml", resource_anchors=(img,),
            ),
        ])
        assert len(chains) == 1
        c = chains[0]
        assert c.confirmed_reachable is True
        assert c.confidence is Confidence.HIGH
        assert c.resources == ["docker.io/library/redis"]
        assert "docker.io/library/redis" in c.reachability_note

    def test_falls_back_when_image_anchors_disjoint(self) -> None:
        build = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/python",
        )
        runtime = ResourceAnchor(
            kind="oci_image", identity="docker.io/acme/app",
        )
        chains = r.match([
            make_failing(
                "DF-001", "Dockerfile", resource_anchors=(build,),
            ),
            make_failing(
                "K8S-001", "k8s/app.yaml", resource_anchors=(runtime,),
            ),
        ])
        # Disjoint identities -> falls through to the per-pair
        # cross-product co-occurrence fallback (1 dockerfile x 1
        # manifest = 1 unconfirmed chain).
        assert len(chains) == 1
        c = chains[0]
        assert c.confirmed_reachable is False
        assert c.reachability_note == ""
        assert sorted(c.resources) == ["Dockerfile", "k8s/app.yaml"]

    def test_one_confirmed_chain_per_image_identity(self) -> None:
        # Two distinct images, each unpinned at both build and
        # runtime ends. Expect two confirmed chains (one per image),
        # NOT four (no per-pair cross-product over confirmed legs).
        img_a = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/nginx",
        )
        img_b = ResourceAnchor(
            kind="oci_image", identity="ghcr.io/acme/api",
        )
        chains = r.match([
            make_failing(
                "DF-001", "nginx/Dockerfile",
                resource_anchors=(img_a,),
            ),
            make_failing(
                "DF-001", "api/Dockerfile", resource_anchors=(img_b,),
            ),
            make_failing(
                "K8S-001", "k8s/nginx.yaml",
                resource_anchors=(img_a,),
            ),
            make_failing(
                "K8S-001", "k8s/api.yaml", resource_anchors=(img_b,),
            ),
        ])
        confirmed = [c for c in chains if c.confirmed_reachable]
        unconfirmed = [c for c in chains if not c.confirmed_reachable]
        assert len(confirmed) == 2
        assert {c.resources[0] for c in confirmed} == {
            img_a.identity, img_b.identity,
        }
        # Every leg contributed to a confirmed pair, no fallback fires.
        assert unconfirmed == []

    def test_partial_match_keeps_unmatched_legs_in_fallback(self) -> None:
        # One image matches across legs (confirmed); a second
        # dockerfile and a second manifest with no matching anchor
        # fall through to per-pair cross-product (one fallback chain
        # for the leftover pair).
        shared = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/redis",
        )
        chains = r.match([
            make_failing(
                "DF-001", "redis/Dockerfile",
                resource_anchors=(shared,),
            ),
            make_failing("DF-001", "worker/Dockerfile"),
            make_failing(
                "K8S-001", "k8s/redis.yaml",
                resource_anchors=(shared,),
            ),
            make_failing("K8S-001", "k8s/worker.yaml"),
        ])
        confirmed = [c for c in chains if c.confirmed_reachable]
        unconfirmed = [c for c in chains if not c.confirmed_reachable]
        assert len(confirmed) == 1
        assert confirmed[0].resources == ["docker.io/library/redis"]
        # Only the unmatched dockerfile x unmatched manifest pair
        # makes it into the fallback — confirmed legs are excluded.
        assert len(unconfirmed) == 1
        assert sorted(unconfirmed[0].resources) == [
            "k8s/worker.yaml", "worker/Dockerfile",
        ]

    def test_partial_anchor_match_keeps_finding_in_fallback(self) -> None:
        # A single DF-001 finding carries TWO oci_image anchors
        # ({python, alpine}); a K8S-001 finding carries {python,
        # redis}. The python pair confirms, but alpine on the
        # Dockerfile and redis on the manifest stay unmatched. The
        # finding should still feed the file-pair fallback so the
        # operator gets the "audit alpine/redis on these files"
        # triage prompt — suppressing the finding entirely after a
        # single anchor match would drop that signal.
        python = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/python",
        )
        alpine = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/alpine",
        )
        redis = ResourceAnchor(
            kind="oci_image", identity="docker.io/library/redis",
        )
        chains = r.match([
            make_failing(
                "DF-001", "Dockerfile",
                resource_anchors=(python, alpine),
            ),
            make_failing(
                "K8S-001", "k8s/app.yaml",
                resource_anchors=(python, redis),
            ),
        ])
        confirmed = [c for c in chains if c.confirmed_reachable]
        unconfirmed = [c for c in chains if not c.confirmed_reachable]
        assert len(confirmed) == 1
        assert confirmed[0].resources == ["docker.io/library/python"]
        # File-pair fallback still emits because the alpine / redis
        # anchors on these findings weren't matched.
        assert len(unconfirmed) == 1
        assert sorted(unconfirmed[0].resources) == [
            "Dockerfile", "k8s/app.yaml",
        ]
