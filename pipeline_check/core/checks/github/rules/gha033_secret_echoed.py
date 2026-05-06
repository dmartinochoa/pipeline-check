"""GHA-033 — ``run:`` body echoes / prints a secret value to the build log."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-033",
    title="Secret value echoed / printed in a run: block",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values from a script. GitHub's log "
        "redaction is a best-effort string match — it doesn't catch "
        "base64 / urlencoded / partial substrings, and any caller "
        "that retrieves the raw log via the API gets the unredacted "
        "stream. If you need to confirm the secret exists, log a "
        "boolean (``[ -n \"$X\" ] && echo set || echo unset``) or a "
        "fingerprint (``echo \"$X\" | sha256sum | head -c8``), never "
        "the value itself."
    ),
    docs_note=(
        "Two distinct shapes are flagged: (1) printing a secret "
        "context expression directly, e.g. ``echo \"${{ secrets.X }}\"`` "
        "or ``cat <<<${{ secrets.X }}``; (2) printing an env var "
        "whose value comes from a secret, when the surrounding step's "
        "``env:`` declares it as ``X: ${{ secrets.X }}``. The first "
        "is the obvious foot-gun; the second is the indirect form "
        "that slips past lint passes that only scan for ``${{ "
        "secrets...}}`` literals."
    ),
)

#: Print-like commands whose first non-flag argument is what we treat
#: as the printed value. Matched as the first token in a logical line.
_PRINT_HEAD_RE = re.compile(
    r"(?:^|\n|\s|;|&|\|)"
    r"(?:echo|printf|cat|tee|print)"
    r"(?:\s+-\w+)*"
    r"\s+",
)

#: A ``${{ secrets.NAME }}`` (or ``env.NAME`` referencing a secret)
#: directly in a printed argument. Uses double-brace markers literal.
_PRINTED_SECRET_CTX_RE = re.compile(
    r"\$\{\{\s*secrets\.\w+\s*\}\}",
)


def _step_secret_env_vars(step: dict[str, Any]) -> set[str]:
    """Names of step-level env vars whose value references ``secrets.*``."""
    out: set[str] = set()
    env = step.get("env")
    if not isinstance(env, dict):
        return out
    for name, value in env.items():
        if isinstance(value, str) and "secrets." in value and "${{" in value:
            out.add(str(name))
    return out


def _scan_for_printed_secret(run: str, secret_env_names: set[str]) -> bool:
    """Return True when *run* prints a secret context expression or a
    secret-bound env var on a line that begins with a print-like
    command.

    The check is per-line: a step that legitimately writes ``"$X"`` to
    a sealed file (``$X > /tmp/state``) doesn't trigger because the
    redirect terminates the printed argument list. The print regex
    only inspects the head of each pipeline-segment.
    """
    for raw_line in run.splitlines():
        # Collapse line continuations / leading whitespace; segment on
        # ``;`` and ``&&`` / ``||`` so a line like ``cmd && echo $X`` is
        # checked as the ``echo $X`` portion only.
        for segment in re.split(r"(?:&&|\|\||;)", raw_line):
            seg = segment.strip()
            if not seg:
                continue
            head_m = re.match(r"^(?:echo|printf|cat|tee|print)\b", seg)
            if not head_m:
                continue
            # Direct ``${{ secrets.X }}`` reference in the printed args.
            if _PRINTED_SECRET_CTX_RE.search(seg):
                return True
            # Indirect: env var that resolves to a secret. Match
            # ``$NAME`` / ``${NAME}`` / ``"$NAME"`` etc.
            for name in secret_env_names:
                ref = re.compile(rf"\${{{name}}}|\$\b{re.escape(name)}\b")
                if ref.search(seg):
                    return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            secret_env = _step_secret_env_vars(step)
            if _scan_for_printed_secret(run, secret_env):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No ``run:`` block prints a secret value to the build log."
        if passed else
        f"{len(offenders)} ``run:`` block(s) print secret values to "
        f"the build log: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Log redaction is "
        f"best-effort — substrings, base64-encoded copies, and "
        f"partial echoes evade it, and API log readers see the raw "
        f"stream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
