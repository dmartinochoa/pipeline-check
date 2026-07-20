"""GHA-045, caller-controlled ``ref`` input fed straight into ``actions/checkout``.

A ``workflow_dispatch`` or ``workflow_call`` input is a *caller-
controlled* value. When the workflow takes that input and uses it
verbatim as the ``ref:`` of ``actions/checkout``, the caller picks
which tree the privileged workflow executes. That's a Direct-PPE
primitive: any actor allowed to dispatch the workflow (often
``write`` permission, but ``workflow_dispatch`` can be granted more
broadly via repository roles or org-level rulesets) can point the
checkout at an arbitrary branch, tag, fork ref, or fully-qualified
SHA and run whatever it contains with secrets in scope.

The same shape applies to reusable workflows: a caller workflow
passes a ref through ``with:``, and the callee checks it out
without validation.

Distinct from GHA-002 (which catches ``ref: ${{ github.event."
"pull_request.head.sha }}`` on ``pull_request_target``) and GHA-046
(manual ``gh pr checkout`` / ``git fetch origin pull/<N>``).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers

RULE = Rule(
    id="GHA-045",
    title="Caller-controlled ref input feeds actions/checkout",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829", "CWE-940"),
    recommendation=(
        "Validate the ``ref`` input against an allow-list (a regex "
        "for ``refs/heads/release-*``, an explicit set of permitted "
        "tags, or a 40-char SHA match) BEFORE passing it to "
        "``actions/checkout``. If the workflow only needs to build "
        "release tags, hard-code the ref or derive it from "
        "``github.event.release.tag_name`` (still attacker-"
        "influenced, but at least scoped to a release event). For "
        "reusable workflows, document that the callee assumes "
        "callers have already validated the ref, and pin every "
        "caller to a known list of refs."
    ),
    docs_note=(
        "``workflow_dispatch`` / ``workflow_call`` inputs land in "
        "``${{ inputs.<name> }}``. Feeding that directly into the "
        "``ref:`` of ``actions/checkout`` means the caller picks "
        "which commit runs in this workflow's privileged context "
        "(secrets, ``GITHUB_TOKEN``, environment approvals already "
        "satisfied). The callee can't tell whether the ref points "
        "at a vetted branch, a private fork's tip, or an attacker-"
        "controlled SHA. The rule fires on ``ref:`` values whose "
        "expression resolves to an ``inputs.*`` reference, walking "
        "any ``${{ ... }}`` expression that names an input field."
    ),
    known_fp=(
        "Reusable workflows that ARE the trust boundary (the callee "
        "is documented as the authoritative checkout entrypoint and "
        "every caller is internal / pinned by SHA) accept this "
        "shape by design. The rule still surfaces these so the "
        "author can document the contract in a "
        "``.pipelinecheckignore`` rationale; suppress with the "
        "caller-list cite.",
    ),
    incident_refs=(
        "Snyk ``GitHub Actions abuse via workflow_dispatch`` "
        "research (2023) showed reusable build workflows that "
        "accepted a ``ref`` input and checked it out without "
        "validation. An attacker with workflow_dispatch permission "
        "(commonly granted to broader sets of actors than push) "
        "pointed the checkout at a fork SHA and exfiltrated the "
        "production deploy credentials.",
    ),
    exploit_example=(
        "# Vulnerable: caller picks the ref.\n"
        "name: build-release\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      ref:\n"
        "        description: 'Tag or branch to build'\n"
        "        required: true\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ inputs.ref }}      # caller controls\n"
        "      - run: make release\n"
        "        env:\n"
        "          SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}\n"
        "\n"
        "# Attack: any actor with workflow_dispatch permission opens\n"
        "# the API and dispatches with ``ref: refs/pull/123/head`` (a\n"
        "# fork PR). The privileged workflow checks out the attacker-\n"
        "# controlled tree and runs ``make release`` with the signing\n"
        "# key in scope. No code review, no PR merge — one API call.\n"
        "\n"
        "# Safe: validate the ref before use.\n"
        "      - name: Validate ref\n"
        "        run: |\n"
        "          case \"$REF\" in\n"
        "            refs/tags/v*) ;;\n"
        "            *) echo \"refusing $REF\"; exit 1 ;;\n"
        "          esac\n"
        "        env:\n"
        "          REF: ${{ inputs.ref }}\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ inputs.ref }}"
    ),
)


# ``${{ inputs.<name> }}`` reference inside a string value, plus the
# equally-valid ``workflow_dispatch`` spelling
# ``${{ github.event.inputs.<name> }}``. The input-name capture is
# unused, we only need to know one is present. ``\b`` before ``inputs``
# keeps ``xinputs.y`` from matching.
_INPUTS_REF_RE = re.compile(
    r"\$\{\{\s*(?:github\.event\.)?inputs\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
)

# A workflow accepts an input if it has ``workflow_dispatch`` or
# ``workflow_call`` triggers. Bare-key ``on:`` is normalized by
# ``workflow_triggers``.
_INPUT_TRIGGERS = frozenset({"workflow_dispatch", "workflow_call"})


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    if not triggers & _INPUT_TRIGGERS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow does not accept workflow_dispatch / "
                "workflow_call inputs."
            ),
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            # Match ``actions/checkout@<anything>``. Forks like
            # ``my-org/checkout`` ship the same code but are
            # author-controlled, out of scope here.
            if not uses.lower().startswith("actions/checkout@"):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            ref = with_block.get("ref")
            if isinstance(ref, str) and _INPUTS_REF_RE.search(ref):
                offenders.append(f"{job_id}[{idx}]")
                locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No ``actions/checkout`` step uses a caller-controlled "
        "``inputs.*`` value as its ``ref``."
        if passed else
        f"{len(offenders)} ``actions/checkout`` step(s) take their "
        f"``ref:`` directly from a caller-supplied input: "
        f"{', '.join(offenders)}. The caller picks which commit "
        f"runs in this workflow's privileged context."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
