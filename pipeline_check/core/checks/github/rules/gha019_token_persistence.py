"""GHA-019. GITHUB_TOKEN written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Workflow, iter_jobs, iter_steps

_TOKEN_PERSIST_RE = re.compile(
    r"GITHUB_TOKEN.*(?:>>?\s|tee\s)"
    r"|>>?\s*\$GITHUB_ENV.*GITHUB_TOKEN"
    r"|\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}.*>>?"
    r"|\$\{\{\s*secrets\.\w+\s*\}\}.*>>?\s*"           # any secret redirected
    r"|>>?\s*\$GITHUB_OUTPUT.*(?:GITHUB_TOKEN|secrets)"  # secrets to GITHUB_OUTPUT
    r"|>>?\s*\$GITHUB_STATE.*(?:GITHUB_TOKEN|secrets)"   # secrets to GITHUB_STATE
)

RULE = Rule(
    id="GHA-019",
    title="GITHUB_TOKEN written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. "
        "Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the "
        "step that needs it."
    ),
    docs_note=(
        "Detects patterns where `GITHUB_TOKEN` is written to files, "
        "environment files (`$GITHUB_ENV`), or piped through `tee`. "
        "Persisted tokens survive the step boundary and can be "
        "exfiltrated by later steps, uploaded artifacts, or cache "
        "entries, turning a scoped credential into a long-lived one."
    ),
    exploit_example=(
        "# Vulnerable: token written to a file that survives the\n"
        "# step boundary and lands in the upload-artifact bundle.\n"
        "jobs:\n"
        "  build:\n"
        "    permissions: { contents: write, packages: write }\n"
        "    steps:\n"
        "      - run: echo \"${{ secrets.GITHUB_TOKEN }}\" > /tmp/token\n"
        "      - run: make build                   # writes /tmp/token\n"
        "                                          # into ./dist/\n"
        "      - uses: actions/upload-artifact@<sha>\n"
        "        with:\n"
        "          name: build-output\n"
        "          path: dist/\n"
        "\n"
        "# Attack: any contributor (or, on public repos, anyone)\n"
        "# downloads the artifact:\n"
        "#\n"
        "#   gh run download <run-id> -n build-output\n"
        "#   cat build-output/tmp/token            # full GITHUB_TOKEN\n"
        "#\n"
        "# The token is scoped to the workflow's permissions block —\n"
        "# in this case write to ``contents`` and ``packages``,\n"
        "# enough to push tampered binaries to GHCR or rewrite the\n"
        "# branch the workflow runs on. Composes with SCM-001\n"
        "# (unprotected default branch) into XPC-004's \"open a PR,\n"
        "# fetch artifact, ship malicious binary\" loop.\n"
        "\n"
        "# Other persistence patterns the rule catches:\n"
        "#   echo \"TOKEN=$GITHUB_TOKEN\" >> $GITHUB_ENV\n"
        "#   echo \"::set-output name=tok::$GITHUB_TOKEN\"\n"
        "#   echo \"$SECRET\" | tee /tmp/cache/secret\n"
        "\n"
        "# Safe: use the token inline in the step that needs it; never\n"
        "# write it anywhere that survives the step's environment:\n"
        "      - run: gh release create v1.0.0 dist/*\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
    ),
)


def check(path: str, doc: dict[str, Any], wf: Workflow | None = None) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if _TOKEN_PERSIST_RE.search(run):
                name = step.get("name") or step.get("id") or "unnamed"
                offenders.append(f"{job_id}.{name}")
    passed = not offenders
    # When this workflow is a resolved callee invoked with
    # ``secrets: inherit``, the persistence vector is strictly
    # broader: every caller secret crosses the boundary, so a
    # ``echo $SECRET >> file`` pattern leaks the caller's universe.
    # Annotate the description so report readers see the chain.
    inherit_note = ""
    if wf is not None and wf.inherits_secrets:
        inherit_note = (
            " (callee inherits caller secrets via ``secrets: inherit``)"
        )
    desc = (
        "No GITHUB_TOKEN persistence patterns detected in this workflow."
        if passed else
        f"GITHUB_TOKEN written to persistent storage in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}." + inherit_note
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
