# Writing an attack chain

How to add a new entry to the [attack-chain catalog](attack_chains.md).

A chain correlates multiple findings into a higher-order narrative.
[`AC-001`](attack_chains.md#ac-001) doesn't fire on `GHA-002` alone or
`GHA-005` alone — it fires when both land on the *same workflow*,
because that combination is exactly how the PyTorch supply-chain
compromise worked. Each chain ships with a short prose summary, a
per-instance narrative, and MITRE ATT&CK technique IDs that downstream
SARIF consumers can pivot on.

A chain is one Python module under
`pipeline_check/core/chains/rules/` exporting two names:

| Name    | Type         | Purpose                                                      |
|---------|--------------|--------------------------------------------------------------|
| `RULE`  | `ChainRule`  | Static metadata (id, title, severity, MITRE, prose, refs)    |
| `match` | callable     | `match(findings) -> list[Chain]` — when the chain triggers   |

The engine walks `rules/` at import time and runs every `(RULE, match)`
pair against the full finding list. No registration call needed; dropping
a file in is enough.

## File naming

Filename pattern: `<id_lower>_<short_slug>.py`.

```
chains/rules/ac001_fork_pr_credential_theft.py
chains/rules/ac010_self_hosted_runner_env_exfil.py
chains/rules/ac013_caller_runner_token_persist.py
```

The numeric portion controls discovery order (mirroring the per-provider
rule convention in [Adding a rule](writing_a_rule.md)). Modules whose
name starts with `_` are skipped, so shared helpers can coexist.

## The minimal chain

```python
"""AC-013 — Caller-Controlled Runner with Token Persistence (GitHub Actions)."""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-013",
    title="Caller-Controlled Runner with Token Persistence",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow's ``runs-on:`` is computed from an attacker-"
        "controllable expression (GHA-036) AND a step in the same "
        "workflow writes ``GITHUB_TOKEN`` to persistent storage "
        "(GHA-019)..."
    ),
    mitre_attack=(
        "T1078",      # Valid Accounts
        "T1552.001",  # Unsecured Credentials: in Files
        "T1133",      # External Remote Services
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://docs.github.com/en/actions/security-for-github-actions/...",
    ),
    recommendation=(
        "Break either leg of the chain. (a) Hard-code ``runs-on:``... "
        "(b) Stop writing ``GITHUB_TOKEN`` to disk..."
    ),
    providers=("github",),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-036", "GHA-019"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-036"], ck_map["GHA-019"]]
        narrative = f"In `{resource}`:\n  1. ...\n  2. ...\n  3. ..."
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-036", "GHA-019"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
```

Read any existing `chains/rules/<id>_<slug>.py` for the canonical
shape — the catalog has 14 examples to crib from.

### `ChainRule` fields

| Field              | Required | Notes                                                                    |
|--------------------|----------|--------------------------------------------------------------------------|
| `id`               | yes      | `AC-NNN`. Globally unique. Matches the filename's numeric portion.       |
| `title`            | yes      | One short sentence. Appears in tables, SARIF, terminal output.           |
| `severity`         | yes      | Composite severity. `CRITICAL` is typical — chains are always worse than their legs. |
| `summary`          | yes      | One paragraph. Surfaced as the SARIF rule `fullDescription`.             |
| `mitre_attack`     | no       | Tuple of MITRE ATT&CK technique IDs (`"T1195.002"`). Surfaces as SARIF tags `mitre/T<NNNN>`. |
| `kill_chain_phase` | no       | Free-form label, e.g. `"initial-access -> exfiltration"`.                |
| `references`       | no       | Tuple of URLs / CVE IDs / incident write-ups.                            |
| `recommendation`   | no       | Cross-finding remediation prose. Typically "break either leg".           |
| `providers`        | no       | Provider scoping (`("github",)`, `("aws", "terraform", "cloudformation")`). Empty = provider-agnostic. Used by `--list-chains` and engine short-circuiting. |

### The `match` callable

`match(findings) -> list[Chain]` receives the **full** finding list
(passed AND failed; filter as needed) and returns zero or more
`Chain` instances. Returning multiple is fine: the same chain pattern
firing in two different workflow files emits two `Chain` objects, one
per resource.

Always pull `confidence` from `min_confidence(triggers)` — a chain is
only as trustworthy as its weakest leg.

## Helpers

The chain engine ships four helpers in `pipeline_check.core.chains.base`.

### `failing(findings, *check_ids)`

Returns failing findings whose `check_id` is in the allowlist. Cheaper
than walking the full list manually.

```python
from ..base import failing

triggers = failing(findings, "GHA-012", "GHA-016", "GHA-019")
```

### `has_failing(findings, check_id)`

Boolean variant for "did this check fire at all". Useful for quick gate
conditions before the heavier resource-grouping work.

### `group_by_resource(findings, required)`

Groups failing findings by resource and **only** keeps resources where
**every** check in `required` fired. The right helper when the chain
must fire on a *single* file or AWS resource (otherwise you're
correlating findings from unrelated workflows).

```python
grouped = group_by_resource(findings, ["GHA-036", "GHA-019"])
# {".github/workflows/release.yml": {"GHA-036": Finding(...), "GHA-019": Finding(...)}}
```

### `min_confidence(findings)`

Returns the lowest confidence among the input findings (`LOW > MEDIUM > HIGH`
on the rank scale). The chain's overall confidence is bottlenecked by
its weakest leg.

## Same-resource vs cross-resource pairing

This is the most common design call. Two patterns:

- **Same-resource pairing**: use `group_by_resource(findings, [...])`.
  The chain only fires when every leg lands on the *same* file / ARN.
  AC-009 (Supply Chain Repo Poisoning) and AC-013 use this — a
  `secrets: inherit` in workflow A and an unpinned reusable in
  workflow B aren't the same call site.
- **Cross-resource pairing**: walk `failing(findings, ...)` directly
  and accept any combination. AC-005 (Unsigned Artifact to Production)
  uses this — the build-side and deploy-side findings live in
  different files by definition.

## OR-of-legs

Some chains fire on `A AND (B OR C)`. AC-010 is the canonical example:
GHA-012 plus *either* GHA-016 *or* GHA-019. Don't try to express that
with `group_by_resource` — write a small custom resource-walker:

```python
def match(findings):
    by_res: dict[str, dict[str, Finding]] = {}
    for f in failing(findings, "GHA-012", "GHA-016", "GHA-019"):
        by_res.setdefault(f.resource, {})[f.check_id] = f
    out = []
    for resource, ck_map in by_res.items():
        if "GHA-012" not in ck_map:
            continue
        secondary = [c for c in ("GHA-016", "GHA-019") if c in ck_map]
        if not secondary:
            continue
        ...
```

Cross-reference [`ac010_self_hosted_runner_env_exfil.py`](https://github.com/dmartinochoa/pipeline-check/blob/master/pipeline_check/core/chains/rules/ac010_self_hosted_runner_env_exfil.py)
for the complete pattern.

## Tests

Add a `class TestChain<ID>` to `tests/test_attack_chains.py`. The
canonical test set is six tests:

```python
class TestChainAC013:
    """AC-013 — Caller-Controlled Runner with Token Persistence."""

    WF = ".github/workflows/release.yml"

    def test_fires_when_both_legs_on_same_workflow(self):
        out = chains_pkg.evaluate([_f("GHA-036", self.WF), _f("GHA-019", self.WF)])
        ac13 = [c for c in out if c.chain_id == "AC-013"]
        assert len(ac13) == 1
        assert ac13[0].severity is Severity.CRITICAL
        assert "T1552.001" in ac13[0].mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        ...

    def test_does_not_fire_when_only_targeting_leg_fails(self):
        ...

    def test_does_not_fire_when_only_persistence_leg_fails(self):
        ...

    def test_does_not_fire_when_legs_passed(self):
        # Findings present but green
        ...

    def test_confidence_inherits_minimum(self):
        out = chains_pkg.evaluate([
            _f("GHA-036", self.WF, confidence=Confidence.HIGH),
            _f("GHA-019", self.WF, confidence=Confidence.LOW),
        ])
        assert next(c for c in out if c.chain_id == "AC-013").confidence is Confidence.LOW
```

The `_f` helper is already defined at the top of `test_attack_chains.py`.

### Bump the engine lock-set

`TestEngine::test_list_rules_discovers_all_chains` carries an explicit
set of every chain ID:

```python
def test_list_rules_discovers_all_chains(self):
    rule_ids = {r.id for r in chains_pkg.list_rules()}
    assert rule_ids == {
        "AC-001", ..., "AC-013", "AC-014",
    }
```

Add your new ID. The lock-set exists so adding a chain is an explicit
decision — accidentally landing one without bumping this set fails
the test.

## Doc generation

The catalog page at [attack_chains.md](attack_chains.md) is regenerated
from the registry:

```bash
python scripts/gen_attack_chains_doc.py
```

`tests/test_attack_chains_doc.py` fails until the regenerated doc is
committed. Two checks enforce currency:

- `test_chain_catalog_doc_in_sync` — the doc's chain catalog must
  match the live registry exactly.
- `test_every_registered_chain_has_a_card` — every registered chain
  must have a section card with `{ #ac-NNN }` anchor markup.

## README count claim

The top-of-README tagline counts attack chains:

```markdown
**430+ checks** across **12 providers**, ..., plus **N attack chains** ...
```

Bump `N` to match the new catalog size. `tests/test_doc_claims.py`
auto-derives the expected value from the registry, so the test will
fail until you update the literal in `README.md`.

## CHANGELOG

Add a `[Unreleased]` `### Added` entry following the established style
(see AC-013 / AC-014 for the latest examples). Include:

- The trigger combination (`GHA-NNN + GHA-MMM` on the same workflow).
- The threat in one sentence — what the combination unlocks beyond either
  finding alone.
- A **Distinct from** call-out for any nearby chain so reviewers know
  why this isn't a duplicate (AC-013's narrative explicitly contrasts
  with AC-010, for example).
- The MITRE techniques and kill-chain phase.
- The catalog count bump (`Chain catalog: N to N+1`).

## Cross-provider parity

Many threat shapes recur across providers. AC-013 and AC-014 are the
canonical example: the same "caller picks runner + token written to
disk" pattern, ported from GitHub (`GHA-036 + GHA-019`) to GitLab
(`GL-032 + GL-020`). When the underlying rules already exist in
multiple providers' catalogs, write one chain per provider rather
than a single multi-provider chain — the narrative prose, MITRE
references, and recommendation copy are provider-specific in
practice (the GitHub chain talks about `GITHUB_TOKEN`; the GitLab
chain talks about `CI_JOB_TOKEN` / `CI_DEPLOY_TOKEN`). One chain
per provider also keeps `providers=("...",)` accurate for the
`--list-chains` filter.

If a primitive rule the chain depends on doesn't exist in another
provider yet, that's a [rule-coverage decision](writing_a_rule.md),
not a chain-extension blocker. Add the rule first, then the chain.

## What NOT to do

- **Don't** write a chain that fires on a single check. Chains are
  multi-finding correlations by definition; if the threat shows up on
  one finding, it belongs as a check.
- **Don't** edit `docs/attack_chains.md` directly. It's regenerated.
- **Don't** include the chain's MITRE / references prose in multiple
  places (the registry was the whole point of `ChainRule`).
- **Don't** silently swallow a `match` failure. The engine catches
  exceptions defensively (a buggy chain rule must not abort the
  evaluation of others), but uncaught crashes are a real bug — the
  test suite is where they should surface.
