"""HELM-003. Chart dependency declared on a non-HTTPS repository.

``dependencies[].repository`` in ``Chart.yaml`` is the URL ``helm
dependency build`` fetches the dependency tarball from. ``http://``
and other plaintext schemes let any on-path attacker swap the
tarball for a backdoored chart on the way in. ``https://``,
``oci://`` (registry-backed, TLS by default), and ``file://``
(monorepo-local sibling) are the safe shapes; the local alias
``@<repo-name>`` is also accepted because it points back at a
``helm repo add``-registered URL whose scheme is enforced by the
caller's local config.
"""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-003",
    title="Chart dependency declared on a non-HTTPS repository",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494", "CWE-319"),
    recommendation=(
        "Switch each ``dependencies[].repository`` value to an "
        "``https://`` chart repo URL, an ``oci://`` registry reference, "
        "or a ``file://`` path for in-repo charts. Plaintext ``http://`` "
        "(and other non-TLS schemes like ``git://``) lets any "
        "on-path attacker substitute the dependency tarball during "
        "``helm dependency build``; ``Chart.lock``'s digest check "
        "(HELM-002) only catches that on the *next* update, not the "
        "compromised pull itself."
    ),
    docs_note=(
        "Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) "
        "and inspects each entry's ``repository:`` URL. Accepted "
        "schemes:\n\n"
        "- ``https://``, chart-museum / OSS chart repos. The default "
        "for public Helm charts.\n"
        "- ``oci://``, registry-hosted charts. TLS is enforced by "
        "the registry, not the URL scheme; we still accept this "
        "shape because Helm 3.8+ pulls OCI charts over HTTPS unless "
        "explicitly configured otherwise.\n"
        "- ``file://``, in-repo dependency. No network surface.\n"
        "- ``@alias``, local alias for a previously registered "
        "``helm repo add`` URL. The scheme of the original URL is "
        "the user's responsibility (and is captured in the chart "
        "consumer's ``~/.config/helm/repositories.yaml``)."
    ),
    exploit_example=(
        "# Vulnerable: ``helm dependency build`` fetches the redis\n"
        "# tarball over plaintext HTTP. Any on-path attacker\n"
        "# (compromised proxy, malicious WiFi, BGP hijack on the\n"
        "# internal mirror) substitutes a backdoored tarball; the\n"
        "# consuming cluster unpacks it into the umbrella chart.\n"
        "# ``Chart.lock``'s digest check (HELM-002) only catches\n"
        "# this on the *next* update, not the compromised pull\n"
        "# itself.\n"
        "apiVersion: v2\n"
        "name: my-app\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.15.4\n"
        "    repository: http://internal-charts.example.com\n"
        "\n"
        "# Safe: HTTPS gives TLS for the fetch; an OCI registry\n"
        "# reference (``oci://``) goes through the registry's TLS\n"
        "# config; a ``file://`` reference reads from disk inside\n"
        "# the same repo, so there's no network surface at all.\n"
        "apiVersion: v2\n"
        "name: my-app\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.15.4\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
        "  - name: postgres\n"
        "    version: 12.1.0\n"
        "    repository: oci://registry.example.com/charts\n"
        "  - name: my-sidecar\n"
        "    version: 0.1.0\n"
        "    repository: file://../sidecar"
    ),
)


_SAFE_SCHEMES = ("https://", "oci://", "file://")


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        # v1 charts use requirements.yaml, outside this check's scope.
        if chart.api_version != "v2":
            continue
        for dep in chart.dependencies:
            repo = dep.get("repository")
            name = dep.get("name") if isinstance(dep.get("name"), str) else "?"
            if not isinstance(repo, str):
                continue
            if not _is_safe_repo(repo):
                offenders.append(
                    f"{chart.name}/{name} -> {repo}"
                )
                locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart dependency repository uses HTTPS, OCI, or file:// "
        "(or a local alias)."
        if passed else
        f"{len(offenders)} dependency repo(s) on a non-HTTPS scheme: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )


def _is_safe_repo(repo: str) -> bool:
    s = repo.strip()
    if not s:
        # Empty repository fields don't reach the network, treat as
        # not-an-offender. A separate schema check could flag the
        # missing field, but it's outside this rule's scope.
        return True
    if s.startswith("@"):
        return True
    lower = s.lower()
    return any(lower.startswith(scheme) for scheme in _SAFE_SCHEMES)
