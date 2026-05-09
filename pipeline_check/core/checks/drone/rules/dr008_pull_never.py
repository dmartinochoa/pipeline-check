"""DR-008. Step uses ``pull: never`` (skips registry verification)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline, iter_services, iter_steps, step_label

RULE = Rule(
    id="DR-008",
    title="Step uses ``pull: never`` (skips registry verification)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-IMMUTABLE",),
    cwe=("CWE-1357",),
    recommendation=(
        "Drop the ``pull: never`` directive (or change it to "
        "``pull: always`` / ``pull: if-not-exists``). "
        "``pull: never`` tells the Drone agent to skip the "
        "registry round-trip entirely, so the agent runs "
        "whatever image bytes it cached on a previous build "
        "without re-verifying the digest. If a compromised image "
        "ever landed in the agent's local cache (a poisoned "
        "registry tag, a manual ``docker pull`` during a debug "
        "session, a co-resident workload that pulled a "
        "malicious image), the cached bytes keep running until "
        "an operator manually clears the cache. ``pull: always`` "
        "(the Drone default) re-fetches and verifies on every "
        "build; ``pull: if-not-exists`` is acceptable when the "
        "image is digest-pinned (DR-001) so the cache key is "
        "content-addressed."
    ),
    docs_note=(
        "Drone supports three ``pull:`` policies on a step: "
        "``always`` (re-fetch + verify on every build, the "
        "default), ``if-not-exists`` (use cache when present, "
        "otherwise pull), and ``never`` (use cache only). The "
        "``never`` policy is the dangerous one because it skips "
        "the digest verification an ``always`` pull would "
        "perform, and there's no out-of-band signal that the "
        "cached image is the one the manifest names. The rule "
        "fires on either steps or services declaring "
        "``pull: never``. ``pull: if-not-exists`` is treated as "
        "acceptable: it's tolerable when paired with a "
        "digest-pinned ``image:`` (DR-001) and a deliberate "
        "operational decision; the explicit-skip case "
        "(``never``) is what TAINT-class supply-chain attacks "
        "lean on."
    ),
    known_fp=(
        "Air-gapped or registry-pinned environments sometimes "
        "set ``pull: never`` deliberately because the agent "
        "never has registry access in the first place. "
        "Suppress via ignore-file when this is the deliberate "
        "shape; the runner's network isolation then carries "
        "the integrity guarantee instead of the registry "
        "round-trip.",
    ),
)


def _pull_value(node: dict[str, Any]) -> str | None:
    """Return the normalized ``pull:`` value of *node*, or None.

    Drone accepts both string forms (``always`` / ``if-not-exists``
    / ``never``) and the deprecated boolean ``pull: false`` —
    YAML treats the latter as a real ``False``, and Drone reads
    that as the equivalent of ``never``. Strings are lowered and
    stripped; ``False`` is normalized to ``"never"``. Anything
    else returns None.
    """
    value = node.get("pull")
    if isinstance(value, bool):
        return "never" if value is False else None
    if isinstance(value, str):
        return value.strip().lower()
    return None


def check(pipeline: Pipeline) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        if _pull_value(step) == "never":
            offenders.append(f"steps.{step_label(step, idx)}")
    for idx, svc in iter_services(pipeline):
        if _pull_value(svc) == "never":
            offenders.append(
                f"services.{step_label(svc, idx, kind='services')}"
            )
    passed = not offenders
    desc = (
        "No step or service uses ``pull: never``."
        if passed else
        f"{len(offenders)} step(s) / service(s) declare "
        f"``pull: never``: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
