"""HELM-015. OCI chart dependency pinned only by a mutable tag."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-015",
    title="OCI chart dependency pinned only by a mutable tag",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-353", "CWE-494"),
    recommendation=(
        "Bind every ``oci://`` chart dependency to immutable "
        "content. An OCI registry tag (the ``version:`` of an "
        "``oci://`` dependency) is mutable: the registry can serve "
        "different chart bytes under the same ``name`` + "
        "``version`` at any time, unlike a classic chart-museum "
        "``index.yaml`` entry. Commit a ``Chart.lock`` whose entry "
        "for this dependency carries a ``sha256:`` ``digest`` (run "
        "``helm dependency update``), so ``helm dependency build`` "
        "verifies the pulled archive against a fixed hash. An exact "
        "SemVer (HELM-004) is necessary but not sufficient for OCI: "
        "the tag is still rewritable until a digest binds it."
    ),
    docs_note=(
        "Fires on a v2-chart dependency whose ``repository`` is an "
        "``oci://`` URL that is bound only by a mutable tag: its "
        "``version`` is not a ``sha256:`` digest AND no valid "
        "``sha256`` ``digest`` for it exists in ``Chart.lock``.\n\n"
        "Sharpens HELM-003 (which accepts every ``oci://`` repo "
        "unconditionally on the transport axis) and complements "
        "HELM-002 / HELM-004: HELM-004 flags a floating SemVer range "
        "and HELM-002 flags a missing lockfile digest for any "
        "dependency, while this rule is the OCI-specific, "
        "HIGH-severity signal that an OCI tag, even an exact one, is "
        "registry-mutable until a digest binds the content. Reuses "
        "HELM-002's digest-shape helper; no new plumbing."
    ),
    known_fp=(
        "A chart that already commits a ``Chart.lock`` with a "
        "sha256 digest for the dependency passes (the content is "
        "bound). A development chart pulling an internal OCI chart "
        "from a trusted registry may accept the lower assurance; "
        "suppress per dependency with a rationale, but the durable "
        "fix is a committed Chart.lock digest.",
    ),
    incident_refs=(
        "Mutable-reference supply-chain class: an OCI tag re-pushed "
        "to point at different chart content after the reference was "
        "audited, the Helm-registry analog of the mutable "
        "container-image-tag problem the K8s / OCI rules flag.",
    ),
    exploit_example=(
        "# Vulnerable: oci:// dependency bound to a mutable tag, no\n"
        "# Chart.lock digest to verify the pulled archive.\n"
        "# Chart.yaml\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    repository: oci://registry-1.docker.io/bitnamicharts\n"
        "    version: 18.1.5\n"
        "# (no Chart.lock entry with a sha256 digest)\n"
        "\n"
        "# Attack: the registry re-pushes 18.1.5 with backdoored\n"
        "# chart content. helm dependency build pulls the new bytes;\n"
        "# nothing verifies them against a fixed hash.\n"
        "\n"
        "# Safe: commit a Chart.lock with the resolved digest.\n"
        "# Chart.lock\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    repository: oci://registry-1.docker.io/bitnamicharts\n"
        "    version: 18.1.5\n"
        "    digest: sha256:1a2b3c...<64 hex>\n"
    ),
)


def _is_valid_digest(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    s = value.strip().lower()
    if not s.startswith("sha256:"):
        return False
    tail = s.split(":", 1)[1]
    return len(tail) == 64 and all(c in "0123456789abcdef" for c in tail)


def _is_oci(repository: Any) -> bool:
    return (
        isinstance(repository, str)
        and repository.strip().lower().startswith("oci://")
    )


def _locked_digests(chart_lock: dict[str, Any] | None) -> dict[str, str]:
    """``{dependency-name: digest}`` from a parsed Chart.lock."""
    out: dict[str, str] = {}
    if not isinstance(chart_lock, dict):
        return out
    deps = chart_lock.get("dependencies")
    if not isinstance(deps, list):
        return out
    for entry in deps:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        digest = entry.get("digest")
        if isinstance(name, str) and isinstance(digest, str):
            out[name] = digest
    return out


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        if chart.api_version != "v2":
            continue
        locked = _locked_digests(chart.chart_lock)
        for dep in chart.dependencies:
            if not _is_oci(dep.get("repository")):
                continue
            name = dep.get("name") if isinstance(dep.get("name"), str) else "?"
            version = dep.get("version")
            version_str = version if isinstance(version, str) else ""
            # A version that is itself a digest reference is bound.
            if _is_valid_digest(version_str.split("@")[-1].strip()):
                continue
            # A committed Chart.lock digest binds the content.
            if _is_valid_digest(locked.get(name, "")):
                continue
            offenders.append(
                f"{chart.name}/{name} {version_str or '(no version)'}"
            )
            locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every oci:// dependency is digest-bound (Chart.lock digest "
        "or digest reference)."
        if passed else
        f"{len(offenders)} oci:// dependency / dependencies pinned "
        f"only by a mutable tag: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The registry can "
        f"re-push different chart bytes under the same reference; "
        f"commit a Chart.lock sha256 digest."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
