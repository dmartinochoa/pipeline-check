"""GHA-116. Workflow serializes the entire secrets context.

The 2025 GitHub Actions supply-chain wave (tj-actions/changed-files +
reviewdog, CVE-2025-30066, March 2025; the GhostAction campaign,
September 2025) turned secret *harvesting* into the dominant payload:
the injected code grabbed every credential the workflow could see and
shipped them out (to the workflow log in the tj-actions case, to an
attacker endpoint in GhostAction).

The cleanest in-YAML primitive for that is ``${{ toJSON(secrets) }}``.
A named reference (``${{ secrets.NPM_TOKEN }}``) hands a step one
credential; ``toJSON(secrets)`` serializes the WHOLE secrets object into
a single string, so one ``echo`` to the log or one ``curl`` exfiltrates
every secret the job has access to at once. There is almost no
legitimate reason to materialize the entire secrets context, so its
presence in a ``run:`` body, an ``env:`` value, or a ``with:`` input is
a high-signal indicator of a secret-scraping payload (or, at best, a
serious anti-pattern that defeats per-secret scoping and log redaction).

This is distinct from the per-secret rules: GHA-033 flags echoing a
named ``${{ secrets.X }}``; GHA-034 flags ``secrets: inherit`` handing a
reusable workflow all secrets; GHA-116 flags a step turning the whole
secrets object into an exfiltratable blob.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

# ``toJSON(secrets)`` in any wrapping (``fromJSON(toJSON(secrets))``,
# ``format('{0}', toJSON(secrets))``) contains this substring. GitHub
# expression function names are case-insensitive; the ``secrets``
# context is lowercase but we stay permissive.
_TOJSON_SECRETS_RE = re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)

RULE = Rule(
    id="GHA-116",
    title="Workflow serializes the entire secrets context (toJSON(secrets))",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522",),
    recommendation=(
        "Never materialize the whole secrets object. ``toJSON(secrets)`` "
        "puts every credential the job can see into one string, so a "
        "single log line or outbound request exfiltrates all of them at "
        "once (the tj-actions / GhostAction 2025 payload pattern). "
        "Reference only the specific secrets a step needs by name "
        "(``${{ secrets.NPM_TOKEN }}``), bind each to a narrowly-scoped "
        "step ``env:``, and prefer short-lived OIDC tokens over "
        "long-lived secrets. If a downstream action genuinely needs "
        "several secrets, pass them individually rather than the full "
        "context."
    ),
    docs_note=(
        "Fires when ``toJSON(secrets)`` appears in any string the "
        "workflow evaluates: a step ``run:`` body, a step / job / "
        "workflow ``env:`` value, or a step ``with:`` input (the "
        "wrappers ``fromJSON(toJSON(secrets))`` and ``format(..., "
        "toJSON(secrets))`` match too, since they contain the same "
        "substring). HIGH severity, HIGH confidence: serializing the "
        "entire secrets context has no benign per-secret use, so the "
        "false-positive rate is low. The rare legitimate case (handing "
        "every secret to a trusted internal aggregator action) is still "
        "an anti-pattern that defeats per-secret scoping and log "
        "redaction; suppress it per-resource with a rationale. Distinct "
        "from GHA-033 (echoes a named secret), GHA-034 (``secrets: "
        "inherit``), and GHA-057 (secret-scanner output to egress)."
    ),
    known_fp=(
        "A workflow that deliberately passes the full secrets context "
        "to a trusted, audited internal action (a secrets-sync or "
        "vault-bootstrap step) will fire. That is still a broad-surface "
        "anti-pattern, but if the receiving action is vetted, suppress "
        "per-resource with a rationale naming the action.",
    ),
    incident_refs=(
        "tj-actions/changed-files + reviewdog supply-chain attack "
        "(CVE-2025-30066, March 2025): a compromised action dumped the "
        "runner's secrets to the workflow log, affecting 23,000+ repos. "
        "The GhostAction campaign (GitGuardian, September 2025) pushed "
        "malicious workflows that serialized every repository secret and "
        "POSTed them to an attacker endpoint, stealing 3,325 secrets. "
        "``toJSON(secrets)`` is the in-YAML primitive both classes rely "
        "on to grab everything at once: "
        "https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/",
    ),
    exploit_example=(
        "# Vulnerable: the whole secrets object is serialized into an\n"
        "# env var and printed. One log line leaks every secret the job\n"
        "# can read (AWS keys, npm/PyPI tokens, SSH keys, ...).\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          ALL_SECRETS: ${{ toJSON(secrets) }}\n"
        "        run: echo \"$ALL_SECRETS\"\n"
        "\n"
        "# Safe: reference only the one secret the step needs, scoped to\n"
        "# that step's env. The secrets context is never serialized.\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
        "        run: npm publish\n"
    ),
)


def _env_values(block: Any) -> list[str]:
    """String values of an ``env:`` / ``with:`` mapping (one level)."""
    out: list[str] = []
    if isinstance(block, dict):
        for v in block.values():
            if isinstance(v, str):
                out.append(v)
    return out


def _hit(text: Any) -> bool:
    return isinstance(text, str) and bool(_TOJSON_SECRETS_RE.search(text))


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    anchor_jobs: set[str] = set()

    # Workflow-level env: propagates the serialized secrets into every
    # job's environment, so it anchors to all jobs (filled in below).
    workflow_dump = any(_hit(v) for v in _env_values(doc.get("env")))
    if workflow_dump:
        offenders.append("<workflow env>")

    job_ids: list[str] = []
    for job_id, job in iter_jobs(doc):
        if not isinstance(job, dict):
            continue
        job_ids.append(job_id)
        job_hit = False
        for val in _env_values(job.get("env")):
            if _hit(val):
                offenders.append(f"{job_id} (job env)")
                job_hit = True
        for idx, step in enumerate(iter_steps(job)):
            if not isinstance(step, dict):
                continue
            if _hit(step.get("run")):
                offenders.append(f"{job_id}[{idx}] run")
                job_hit = True
            for val in _env_values(step.get("env")):
                if _hit(val):
                    offenders.append(f"{job_id}[{idx}] env")
                    job_hit = True
            for val in _env_values(step.get("with")):
                if _hit(val):
                    offenders.append(f"{job_id}[{idx}] with")
                    job_hit = True
        # Reusable-workflow call jobs (``jobs.<id>.uses:``) have no steps;
        # their job-level ``with:`` / ``secrets:`` mappings carry values
        # across the call boundary and must be scanned too.
        for kind in ("with", "secrets"):
            for val in _env_values(job.get(kind)):
                if _hit(val):
                    offenders.append(f"{job_id} (call {kind})")
                    job_hit = True
        if job_hit:
            anchor_jobs.add(job_id)

    if workflow_dump:
        anchor_jobs.update(job_ids)

    passed = not offenders
    desc = (
        "No step or env value serializes the whole secrets context."
        if passed else
        f"{len(offenders)} location(s) serialize the entire secrets "
        f"context via ``toJSON(secrets)``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. One log line or outbound "
        f"request then exfiltrates every secret the job can read; "
        f"reference only the specific secrets each step needs."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(sorted(anchor_jobs)),
    )
