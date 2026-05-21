"""BB-019, after-script accessing secrets may leak credentials on failure."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

_SECRET_REF_RE = re.compile(
    r"\$\{?(?:BITBUCKET_TOKEN|REPOSITORY_OAUTH_ACCESS_TOKEN)\}?"
    r"|\$\{?[A-Z_]*(?:SECRET|TOKEN|PASSWORD|KEY)[A-Z_]*\}?"
)

RULE = Rule(
    id="BB-019",
    title="after-script references secrets",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Move secret-dependent operations into the main `script:` "
        "block. `after-script` runs even when the step fails and "
        "executes in a separate shell context, credential exposure "
        "here is harder to audit and more likely to persist in logs."
    ),
    docs_note=(
        "Bitbucket's `after-script` runs unconditionally after the "
        "main `script` block (including on failure). If the "
        "`after-script` references secrets or tokens, those values "
        "may leak into build logs or artifacts even when the step "
        "fails unexpectedly. This check detects secret-like variable "
        "references in `after-script` blocks."
    ),
    known_fp=(
        "The detector matches any variable whose name contains "
        "``TOKEN`` / ``SECRET`` / ``PASSWORD`` / ``KEY`` "
        "(case-insensitive). Names that are descriptive rather "
        "than secret (``CACHE_KEY``, ``SORT_KEY``, ``TOKEN_TYPE`` "
        "used as a label, ``API_KEY_NAME`` storing the *name* of "
        "the key rather than its value) trigger the regex even "
        "though they aren't credentials. The rule has no way to "
        "tell from the name alone, suppress per-step via "
        "``--ignore-file`` when the referenced value is benign.",
    ),
    exploit_example=(
        "# Vulnerable: ``after-script`` runs even when the main\n"
        "# script fails. Echoing a secret env var here lands the\n"
        "# value in the build log on every failed build — which\n"
        "# is exactly when the log gets the most attention.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - ./deploy.sh   # uses $DEPLOY_KEY\n"
        "        after-script:\n"
        "          - echo \"Deploy attempted with $DEPLOY_KEY\"   # leaks on failure\n"
        "\n"
        "# Safe: after-script body references only step IDs /\n"
        "# build metadata, never the secret env vars themselves.\n"
        "# Failure diagnostics belong in the main script, where\n"
        "# Bitbucket masks secured-variable values in output.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - ./deploy.sh\n"
        "        after-script:\n"
        "          - echo \"Deploy step $BITBUCKET_BUILD_NUMBER complete.\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        after = step.get("after-script")
        if not isinstance(after, list):
            continue
        for line in after:
            if isinstance(line, str) and _SECRET_REF_RE.search(line):
                offenders.append(loc)
                break
    passed = not offenders
    desc = (
        "No after-script blocks reference secrets."
        if passed
        else f"after-script references secret-like variables in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
