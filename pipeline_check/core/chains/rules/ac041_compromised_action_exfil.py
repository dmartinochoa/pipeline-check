"""AC-041. Compromised action executed and exfiltrated credentials, same run.

Two run-forensics legs on the *same* workflow run:

  * ``RUN-006`` — a known-compromised action (the GHA-040 IOC registry)
    actually executed in that run's logs.
  * ``RUN-003`` (a secret-shaped string leaked in that run's logs) OR
    ``RUN-004`` (that run minted a cloud OIDC token).

Independently, RUN-006 confirms a malicious action ran and RUN-003 /
RUN-004 confirm a credential was exposed. Landing on the *same run* is the
runtime confirmation that the two are one event: the compromised action
executed and a credential left the run in the same execution. The
tj-actions/changed-files (CVE-2025-30066) compromise did exactly this,
printing the harvested secrets into the run log. This is the strongest
signal the tool produces, a supply-chain attack confirmed to have
*succeeded*, not merely been possible, so it warrants incident response,
not triage.

Reachability is structural, not co-occurrence: both legs carry the same
``github:owner/repo#run/<id>`` resource, so they provably happened in one
run (the same execution context, the same log archive). The chain is
emitted ``confirmed_reachable`` at HIGH confidence, the run-history
analog of AC-005's shared-image-digest pairing.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-041",
    title="Compromised action executed and exfiltrated credentials in the same run",
    severity=Severity.CRITICAL,
    summary=(
        "A known-compromised action actually executed in a workflow run "
        "(RUN-006) AND the same run exposed a credential: a secret-shaped "
        "string leaked in its logs (RUN-003) or it minted a cloud OIDC "
        "token (RUN-004). Both legs on one run is the run-history "
        "confirmation that the supply-chain attack succeeded, the "
        "malicious action ran and a credential left the run in the same "
        "execution (the tj-actions/changed-files pattern)."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1552",      # Unsecured Credentials
        "T1567",      # Exfiltration Over Web Service
    ),
    kill_chain_phase=(
        "initial-access (a compromised third-party action is pulled into "
        "the run) -> execution (the malicious action runs) -> "
        "credential-access (a secret is exposed in the run, or an OIDC "
        "token is minted) -> exfiltration (the compromised action ships "
        "the credential out, the leak / mint is the evidence)"
    ),
    references=(
        "https://www.cve.org/CVERecord?id=CVE-2025-30066",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
    ),
    recommendation=(
        "Respond as to a confirmed breach: rotate every credential and "
        "token the affected run could reach (the leaked secret, the "
        "federated cloud role for an OIDC mint, the GITHUB_TOKEN), review "
        "the run's outbound network and any pushes / deployments it made, "
        "and audit downstream systems the credential can reach. Then close "
        "the entry point: pin the action to a known-good commit SHA "
        "(GHA-040 / RUN-006) and stop the credential reaching the log "
        "(RUN-003) or scope the OIDC role's trust policy (RUN-004)."
    ),
    providers=("runs",),
    triggering_check_ids=("RUN-006", "RUN-003", "RUN-004"),
)

#: Credential-exposure legs, either confirms a credential left the run.
_EXFIL_LEGS = ("RUN-003", "RUN-004")


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    for exfil_id in _EXFIL_LEGS:
        grouped = group_by_resource(findings, ["RUN-006", exfil_id])
        for resource, ck_map in grouped.items():
            action = ck_map["RUN-006"]
            exfil = ck_map[exfil_id]
            triggers = [action, exfil]
            exfil_leg = (
                "a secret-shaped string leaked in that same run's logs "
                "(RUN-003), so the compromised action's exfiltration is "
                "visible in the log"
                if exfil_id == "RUN-003"
                else "that same run minted a cloud OIDC token (RUN-004), so "
                "the compromised action could exchange it for the "
                "federated cloud role"
            )
            narrative = (
                f"On run `{resource}`:\n"
                f"  1. A known-compromised action (the GHA-040 IOC "
                f"registry) actually executed in the run's logs "
                f"(RUN-006).\n"
                f"  2. In the same run, {exfil_leg}.\n"
                f"  3. Composite: this is the supply-chain attack confirmed "
                f"to have succeeded. The malicious action ran and a "
                f"credential left the run in one execution, the "
                f"tj-actions/changed-files pattern (printing harvested "
                f"secrets into the log). Treat it as an active breach."
            )
            out.append(Chain(
                chain_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                confidence=min_confidence(triggers),
                summary=RULE.summary,
                narrative=narrative,
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=["RUN-006", exfil_id],
                triggering_findings=triggers,
                resources=[resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=True,
                via_structural=True,
                reachability_note=(
                    f"RUN-006 and {exfil_id} both fired on the same run "
                    f"`{resource}`"
                ),
            ))
    # A run that trips both RUN-003 and RUN-004 alongside RUN-006 should
    # surface a single AC-041, not two. Keep the first (RUN-003) per run.
    seen: set[str] = set()
    deduped: list[Chain] = []
    for c in out:
        if c.resources[0] not in seen:
            seen.add(c.resources[0])
            deduped.append(c)
    return deduped
