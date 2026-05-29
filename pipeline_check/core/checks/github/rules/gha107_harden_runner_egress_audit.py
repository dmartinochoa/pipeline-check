"""GHA-107. harden-runner runs in audit mode (egress not blocked).

step-security/harden-runner is a runtime agent that can enforce a
network-egress allowlist on the runner. It only does so with
``egress-policy: block``. In ``audit`` mode (also the default when the
input is omitted) it records outbound connections to the StepSecurity
dashboard but lets every one through, so a compromised dependency or
action can still ship the OIDC token, ``GITHUB_TOKEN``, or secrets off
the runner.

This is the common half-adoption: a team adds harden-runner expecting
protection but leaves it in audit, getting visibility without
prevention. The fix is one line, so the rule is high-signal and
low-FP. It complements GHA-108 (no egress-control agent at all):
GHA-108 fires when harden-runner is absent, GHA-107 when it's present
but not enforcing.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

#: Canonical action slug (owner/repo, lower-cased) for the egress agent.
_HARDEN_RUNNER = "step-security/harden-runner"

RULE = Rule(
    id="GHA-107",
    title="harden-runner runs in audit mode (egress not blocked)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7", "CICD-SEC-10"),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-693",),  # Protection Mechanism Failure
    recommendation=(
        "Set `egress-policy: block` on the harden-runner step and list "
        "every host the job legitimately reaches under "
        "`allowed-endpoints`. In audit mode harden-runner only records "
        "outbound connections; it does not stop a compromised "
        "dependency or action from exfiltrating `GITHUB_TOKEN`, OIDC "
        "credentials, or secrets. Run once in audit mode to learn the "
        "baseline, then switch to block."
    ),
    docs_note=(
        "step-security/harden-runner runs as a runtime agent on the "
        "runner. With `egress-policy: audit` (also the default when the "
        "input is omitted) it logs outbound traffic but lets every "
        "connection through. Only `egress-policy: block` enforces the "
        "allowlist and drops connections to hosts outside "
        "`allowed-endpoints`. A workflow that adopts harden-runner but "
        "leaves it in audit mode gets visibility, not prevention: the "
        "exfiltration path the agent exists to close stays open.\n\n"
        "Fires for each job whose harden-runner step sets "
        "`egress-policy: audit` or omits the input entirely. A step "
        "pinned to `block` passes. A value the scanner can't resolve "
        "(a `${{ }}` expression) is not flagged."
    ),
    known_fp=(
        "A deliberate audit-only rollout, the recommended first phase "
        "before turning on block, will fire here. Suppress per-job with "
        "a rationale while you collect the egress baseline, then switch "
        "to block and remove the suppression.",
    ),
    incident_refs=(
        "StepSecurity, tj-actions/changed-files compromise (2025): the "
        "injected payload exfiltrated runner secrets over the network. "
        "harden-runner in block mode drops that connection; audit mode "
        "only records it after the fact. "
        "https://www.stepsecurity.io/blog/popular-github-action-"
        "tj-actions-changed-files-is-compromised",
    ),
    exploit_example=(
        "# Vulnerable: harden-runner is present but only auditing. A\n"
        "# compromised dependency pulled by `npm ci` can still POST the\n"
        "# OIDC token to an attacker host; audit mode logs the\n"
        "# connection but does not block it.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: step-security/harden-runner@<sha>\n"
        "        with:\n"
        "          egress-policy: audit\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci && npm run build\n"
        "\n"
        "# Safe: block mode with an explicit allowlist. Any outbound\n"
        "# connection to a host not in `allowed-endpoints` is dropped,\n"
        "# so the exfiltration attempt fails at the network layer.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: step-security/harden-runner@<sha>\n"
        "        with:\n"
        "          egress-policy: block\n"
        "          allowed-endpoints: >\n"
        "            github.com:443\n"
        "            registry.npmjs.org:443\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci && npm run build"
    ),
)


def _is_harden_runner(uses: Any) -> bool:
    if not isinstance(uses, str):
        return False
    slug = uses.split("@", 1)[0].strip().lower()
    return slug == _HARDEN_RUNNER


def _egress_policy(step: dict[str, Any]) -> str | None:
    """Return the lower-cased ``egress-policy`` value, or ``None``.

    ``None`` means the input is absent (harden-runner defaults to
    audit) or the value is a ``${{ }}`` expression the scanner can't
    resolve. The caller distinguishes the two.
    """
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return None
    val = with_block.get("egress-policy")
    if not isinstance(val, str):
        return None
    return val.strip().lower()


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    saw_harden_runner = False
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            if not _is_harden_runner(step.get("uses")):
                continue
            saw_harden_runner = True
            policy = _egress_policy(step)
            if policy == "block":
                continue
            if policy is not None and "${{" in policy:
                # Expression-valued policy: can't tell, don't flag.
                continue
            shown = policy if policy else "unset"
            offenders.append(f"{job_id} (egress-policy: {shown})")
            locations.append(step_location(path, step))

    if not saw_harden_runner:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No harden-runner step to evaluate.",
            recommendation="No action required.", passed=True,
        )

    passed = not offenders
    desc = (
        "Every harden-runner step enforces `egress-policy: block`."
        if passed else
        f"{len(offenders)} harden-runner step(s) do not block egress: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. Audit mode records "
        f"outbound traffic but lets it through, so a compromised "
        f"dependency or action can still exfiltrate the OIDC token, "
        f"`GITHUB_TOKEN`, or secrets."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
