# Attack Chains

A single finding rarely captures the full risk of a CI/CD misconfiguration.
A `pull_request_target` trigger is bad on its own; long-lived AWS credentials
are bad on their own; but the *combination* — on the same workflow — is
exactly how the PyTorch supply-chain compromise worked. Pipeline-Check's
**attack chain** engine correlates findings into those multi-step
narratives and emits one higher-order result per matched chain, mapped to
[MITRE ATT&CK](https://attack.mitre.org/) techniques.

Chains are **additive**. They never replace a finding — they sit on top of
the finding set and highlight the combinations that map to real-world
attack paths. Fix any one leg and the chain breaks.

## Registered chains

| ID | Title | Severity | Providers | Triggering checks |
|----|-------|----------|-----------|-------------------|
| `AC-001` | Fork-PR Credential Theft (`pull_request_target`) | CRITICAL | github | `GHA-002` + `GHA-005` |
| `AC-002` | Script Injection to Unprotected Deploy | CRITICAL | github | `GHA-003` + `GHA-014` |
| `AC-003` | Unpinned Action to Credential Exfiltration | HIGH | github | `GHA-001` + `GHA-005` |
| `AC-004` | Self-Hosted Runner Persistent Foothold | CRITICAL | github | `GHA-002` + `GHA-012` |
| `AC-005` | Unsigned Artifact to Production | HIGH | (cross-provider) | build-side `*-006` / `SIGN-001` + deploy-gate `*-014` / `GCB-009` / `CP-001` / `CP-005` |
| `AC-006` | Cache Poisoning via Untrusted Trigger | HIGH | github | `GHA-002` + `GHA-011` |
| `AC-007` | IAM Privilege Escalation via CodeBuild | CRITICAL | aws / terraform / cloudformation | `CB-002` + (`IAM-002` or `IAM-004`) |
| `AC-008` | Dependency Confusion Window | HIGH | github | `GHA-021` + `GHA-029` |

Run `pipeline_check --list-chains` to see the current set at any time.
Run `pipeline_check --explain-chain AC-001` for the full reference
(summary, narrative, MITRE techniques, kill-chain phase, references,
recommendation).

## How chains surface in output

- **Terminal** — a panel per chain after the findings table, with a
  coloured border matching the chain's severity and the full narrative
  inline.
- **JSON** — `chains` top-level array carrying every field plus
  `triggering_findings: [{check_id, resource}, …]`. Omitted (not empty)
  when the caller passed `--no-chains`, so consumers can distinguish
  "nothing matched" from "not asked for".
- **SARIF** — one rule and one result per chain, tagged `attack-chain`
  plus `mitre/T…` for each technique. GitHub Code Scanning surfaces
  them as top-level alerts.
- **HTML** — an Attack Chains section immediately after the score
  card. Each chain is a bordered card with severity, confidence,
  narrative, triggering checks, MITRE techniques, and references.
- **Markdown** — an Attack Chains H2 between the summary line and the
  Failures table, so a PR comment reader sees the highest-signal
  artifact first.

## Gating CI on chains

```bash
# Fail the gate only on named chains (the team has explicitly
# opted in to blocking these patterns).
pipeline_check --fail-on-chain AC-001 --fail-on-chain AC-007

# Blanket guard: fail if any chain matched at all.
pipeline_check --fail-on-any-chain
```

Chain gates **bypass baseline and ignore-file filtering** — a correlated
attack path is intrinsically a new finding even when the constituent
legs were baselined separately. An `AC-001` match that surfaces after
an OIDC migration partial-rollout would otherwise hide behind two
green baseline suppressions.

## Disabling chain evaluation

```bash
pipeline_check --no-chains
```

Drops the chain correlation pass entirely. The `chains` key is omitted
from the JSON payload. Useful when a downstream consumer doesn't
understand the field, or to shave a few milliseconds off a CI hot
path (chain evaluation is O(findings × rules), cheap in practice).

## Confidence inheritance

A chain is only as trustworthy as its weakest leg. `Chain.confidence`
is set to the minimum confidence among the triggering findings — if
one leg comes from a LOW-confidence blob heuristic, the chain is
reported at LOW confidence even when every other leg is HIGH. The
`--min-confidence` filter applies the same way to chains as to
findings.

## Adding a new chain

Chains are plugin-discovered from `pipeline_check/core/chains/rules/`.
Drop a module named `ac<NNN>_<slug>.py` exporting a `RULE` of type
`ChainRule` and a `match(findings) -> list[Chain]` function. The
engine auto-registers it at import time. See the existing
`ac001_fork_pr_credential_theft.py` for the canonical shape — most
chains only need `group_by_resource(findings, [...])` plus a narrative
template.
