"""GHA-090. ``uses:`` SHA pin references a commit absent from the claimed repo.

Mirrors zizmor's ``impostor-commit`` audit. Detects the attack shape
where ``uses: owner/repo@<sha>`` points at a commit that exists only
in a fork's network, not in the head repository the slug names. SHA
pinning is the canonical mitigation for unpinned actions, but a SHA
that resolves to attacker-controlled code in a fork is just as
exploitable as any other compromised ref.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_metadata[*].sha_membership`` (the per-SHA
``GET /repos/{o}/{r}/commits/{sha}`` membership probe). Without it
the rule passes silently with a note pointing at the flag.

Pairs with GHA-040 (compromised SHA / tag) and GHA-001 (unpinned
``uses:``). HIGH severity, the attack shape carries full code-
execution authority on the runner.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-090",
    title="Action SHA pin references a commit absent from the claimed repo",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829", "CWE-506"),
    recommendation=(
        "Verify the action's expected SHA via the upstream repo's "
        "release / tag history. If the SHA exists only in a fork, "
        "either pin to a canonical SHA on the head repository or "
        "fork the action under your org's control so the network "
        "you depend on is not the attacker's. The impostor-commit "
        "shape was popularized by red-team write-ups, the SHA pin "
        "passes review eyes because reviewers don't query the "
        "network for membership."
    ),
    docs_note=(
        "Reads the per-SHA membership probe from "
        "``ctx.action_metadata[owner/repo].sha_membership`` "
        "(populated by ``--resolve-remote``; the same per-action "
        "metadata pass the GHA-041..043 reputation rules ride on). "
        "A False value means ``GET /repos/{o}/{r}/commits/{sha}`` "
        "ran and came back empty (most commonly a 404, the SHA is "
        "not in the repo's commit graph). When every SHA probed for "
        "an action came back False the rule treats that as "
        "rate-limit noise rather than impostor-commit and passes "
        "silently with a one-line nudge; an attacker has no way to "
        "make every legitimate pin fail at once, so unanimous "
        "failure is a configuration signal, not an attack."
    ),
    known_fp=(
        "Force-pushed branches whose old SHA you pinned at can drop "
        "out of the reachability set even though the SHA was once "
        "legitimate. Re-pin to a SHA that's currently reachable. "
        "Suppress per-finding only after confirming through git "
        "log / the upstream tag history that the SHA wasn't "
        "introduced by a fork.",
    ),
    incident_refs=(
        "Synacktiv / Octoscan write-ups document impostor-commit as "
        "the next-step refinement after SHA pinning becomes "
        "table-stakes. The attack reuses the canonical PR-fork "
        "shape: a contributor fork has commit X that head doesn't, "
        "X gets referenced via ``uses: org/repo@X`` somewhere "
        "downstream, and runtime fetches X over GitHub's per-fork "
        "object pool.",
    ),
    exploit_example=(
        "# Vulnerable: the SHA below resolves only against a fork's\n"
        "# commit pool. ``actions/checkout`` itself never carried\n"
        "# this commit, but GitHub still serves it via the fork-\n"
        "# network when an authenticated workflow asks for it.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<fork-only-sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: SHA that resolves on the head repo.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<canonical-sha>\n"
        "      - run: ./build.sh"
    ),
)


def _iter_sha_uses(
    doc: dict[str, Any],
) -> Iterator[tuple[str, str, str, str]]:
    """Yield ``(label, owner, repo, sha)`` for every ``uses:`` whose
    ref is a 40-char hex SHA.

    Tag / branch refs are not in scope, the impostor-commit attack
    model applies specifically to the SHA-pinning case. The membership
    field on action_metadata is only populated for SHA refs, so a
    tag-only metadata slot also short-circuits gracefully if reached.
    """
    from ..._primitives.sha_ref import SHA_RE
    for job_id, job in iter_jobs(doc):
        job_uses = job.get("uses")
        ref = parse_uses(job_uses)
        if ref and ref.kind in {"remote-action", "remote-workflow"} and SHA_RE.match(ref.ref):
            yield job_id, ref.owner, ref.repo, ref.ref
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            ref = parse_uses(uses)
            if ref and ref.kind in {"remote-action", "remote-workflow"} and SHA_RE.match(ref.ref):
                yield f"{job_id}[{idx}]", ref.owner, ref.repo, ref.ref


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    impostors: list[str] = []
    any_probed = False
    any_confirmed = False
    probed_count = 0
    seen: set[tuple[str, str, str]] = set()
    for label, owner, repo, sha in _iter_sha_uses(doc):
        key = (owner.lower(), repo.lower(), sha)
        if key in seen:
            continue
        seen.add(key)
        meta = ctx.action_metadata.get(f"{owner.lower()}/{repo.lower()}")
        if meta is None or meta.sha_membership is None:
            continue
        if sha not in meta.sha_membership:
            continue
        any_probed = True
        probed_count += 1
        if meta.sha_membership[sha]:
            any_confirmed = True
        else:
            impostors.append(f"{label}: {owner}/{repo}@{sha[:12]}…")
    if not ctx.action_metadata or not any_probed:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No SHA-membership data available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "impostor-commit detection on SHA-pinned action refs."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # When the scan probed at least two SHAs and every single one
    # came back False, treat the shape as resolver / rate-limit
    # noise rather than impostor-commit. An attacker has no plausible
    # way to make every legitimate pin fail at once, so unanimous
    # failure across multiple actions is a configuration signal.
    # Single-SHA all-False is still a real impostor candidate because
    # the per-repo metadata fetch already succeeded as a network
    # canary upstream. Gate on probed_count (not len(seen)) so SHA
    # refs we never actually probed don't dilute the threshold.
    if probed_count >= 2 and impostors and not any_confirmed:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "All SHA-membership probes came back empty; treating "
                "as resolver / rate-limit noise rather than "
                "impostor-commit. Rerun with --gh-token to lift the "
                "unauthenticated rate-limit ceiling."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not impostors
    if passed:
        desc = (
            "Every SHA-pinned action reference resolves to a commit "
            "in the claimed repository's reachability set."
        )
    else:
        sample = "; ".join(impostors[:3])
        if len(impostors) > 3:
            sample += f" (+{len(impostors) - 3} more)"
        desc = (
            f"{len(impostors)} SHA-pinned action reference(s) point "
            f"at a commit absent from the claimed repo: {sample}. "
            f"Impostor-commit setups serve attacker code through "
            f"GitHub's fork-network object pool even though the "
            f"``uses:`` slug names a trusted upstream."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
