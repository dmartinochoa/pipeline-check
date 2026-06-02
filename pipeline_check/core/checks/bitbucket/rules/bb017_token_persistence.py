"""BB-017, repository token written to persistent storage."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts

# A token is "persisted" when a redirect (``>``/``>>``) or ``| tee``
# writes the token reference itself. The redirect must closely follow
# the token (only closing quotes / whitespace between) so the common
# safe idiom ``curl -H "Authorization: Bearer $TOKEN" URL > out.json``
# (where the redirect saves the API RESPONSE, not the token) is not
# matched. ``["'\s]*`` cannot span the URL that sits between the token
# and the redirect in that idiom.
_TOKENS = (
    "BITBUCKET_TOKEN",
    "REPOSITORY_OAUTH_ACCESS_TOKEN",
    "BITBUCKET_STEP_OIDC_TOKEN",
    "BITBUCKET_CLONE_TOKEN",
)
_TOKEN_PERSIST_RE = re.compile(
    "|".join(
        rf"{tok}[\"'\s]*(?:>>?\s|\|\s*tee\s)" for tok in _TOKENS
    )
)

RULE = Rule(
    id="BB-017",
    title="Repository token written to persistent storage",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN "
        "to files or artifacts. Use the token inline in the command "
        "that needs it and let Bitbucket revoke it after the build."
    ),
    docs_note=(
        "Detects patterns where Bitbucket pipeline tokens are "
        "redirected to files or piped through `tee`. Persisted tokens "
        "survive the step boundary and can be exfiltrated by later "
        "steps, artifacts, or cache entries."
    ),
    exploit_example=(
        "# Vulnerable: ``BITBUCKET_TOKEN`` written to a file or\n"
        "# piped to ``tee`` for downstream steps. The token is\n"
        "# meant to live only for the step's duration; persisting\n"
        "# it into an artifact or a cache extends the credential's\n"
        "# lifetime well beyond its intended scope.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - echo \"TOKEN=$BITBUCKET_TOKEN\" >> .env\n"
        "        artifacts: [.env]\n"
        "\n"
        "# Safe: use the token inline in the one command that\n"
        "# needs it. Bitbucket scopes the token to the step's\n"
        "# lifetime and revokes it on exit.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - curl --header \"Authorization: Bearer $BITBUCKET_TOKEN\" \\\n"
        "              \"https://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_FULL_NAME\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        for line in step_scripts(step):
            if _TOKEN_PERSIST_RE.search(line):
                offenders.append(loc)
                break
    passed = not offenders
    desc = (
        "No repository token persistence patterns detected."
        if passed
        else f"Repository token written to persistent storage in: "
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
