"""GHA-033, ``run:`` body echoes / prints a secret value to the build log."""
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
        "redaction is a best-effort string match. It doesn't catch "
        "base64 / urlencoded / partial substrings, and any caller "
        "that retrieves the raw log via the API gets the unredacted "
        "stream. If you need to confirm the secret exists, log a "
        "boolean (``[ -n \"$X\" ] && echo set || echo unset``), "
        "never the value itself. Note: a SHA-256 fingerprint or a "
        "``${X:0:N}`` prefix is not a safe substitute either, those "
        "shapes still slip past the masker and are flagged by "
        "GHA-087 separately."
    ),
    docs_note=(
        "Three shapes are flagged:\n\n"
        "1. **Direct.** A printed argument references a secret context "
        "expression, e.g. ``echo \"${{ secrets.X }}\"`` or "
        "``cat <<<${{ secrets.X }}``.\n"
        "2. **Indirect env var.** A step ``env:`` block resolves a "
        "secret into the env (``X: ${{ secrets.X }}``) and the same "
        "step's ``run:`` echoes the env var (``echo \"$X\"``). Catches "
        "the lint-evading form where no ``${{ secrets...}}`` literal "
        "appears in the run body.\n"
        "3. **Shell trace.** The step enables ``set -x`` / "
        "``set -o xtrace`` AND references a secret-bound env var "
        "anywhere in the body. Shell trace mode dumps every command "
        "with arguments expanded before execution, so a ``curl -H "
        "\"Bearer $TOKEN\"`` line that would normally stay out of the "
        "log lands in the log verbatim. The rule fires once per step "
        "even though many lines may leak.\n\n"
        "Out of scope (deliberate carve-out): inline secret references "
        "in a command's *arguments* without shell trace enabled. "
        "``curl --header \"Authorization: Bearer ${{ secrets.X }}\"`` "
        "doesn't echo the header to stdout — the value goes to the "
        "network, not the log. That class of leak is covered by "
        "GHA-008 (literal credential in YAML) and the network-egress "
        "shape of GHA-057, not GHA-033. ``greylag-ci/cicd-goat`` "
        "scenario 15 sits squarely in this carve-out: a literal hex "
        "token in workflow ``env:`` plus a GET ``curl`` carrying the "
        "credential in an ``Authorization:`` header. GHA-008 fires "
        "on the literal; GHA-033 deliberately does not."
    ),
    exploit_example=(
        "# Vulnerable: ``echo $TOKEN`` (or printing a\n"
        "# ``${{ secrets.X }}`` interpolation) prints the masked\n"
        "# value to stdout. GitHub masks ``$TOKEN`` with ``***``\n"
        "# in the log, but ``set -x`` (or any shell-trace mode)\n"
        "# dumps the literal value because trace output isn't\n"
        "# subject to the mask. Same applies to ``cat`` / ``tee``\n"
        "# of any file the secret was written into.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TOKEN: ${{ secrets.DEPLOY_KEY }}\n"
        "    steps:\n"
        "      - run: |\n"
        "          set -x\n"
        "          curl -H \"Authorization: Bearer $TOKEN\" \\\n"
        "            https://api.example.com/deploy\n"
        "\n"
        "# Safe: don't echo the secret. Drop ``set -x`` (or ensure\n"
        "# it's set only when no secret env vars are in scope).\n"
        "# Pass the secret to curl via a stdin / config file so it\n"
        "# never lands in shell trace output.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TOKEN: ${{ secrets.DEPLOY_KEY }}\n"
        "    steps:\n"
        "      - run: |\n"
        "          curl --config <(echo \"header = \\\"Authorization: Bearer $TOKEN\\\"\") \\\n"
        "            https://api.example.com/deploy"
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

#: Shell trace toggles that turn every subsequent command into a log
#: leak when secret-bound env vars are in scope. Matches either
#: ``set -x`` (possibly bundled with other ``-e`` / ``-o pipefail``
#: flags) or the long form ``set -o xtrace``. The trailing word
#: boundary keeps ``set -xtr`` (not a real shell flag) from matching.
_SHELL_TRACE_RE = re.compile(
    r"(?:^|;|&&|\|\|)\s*set\s+"
    r"(?:[-+][a-zA-Z]*x[a-zA-Z]*\b|-o\s+xtrace\b)",
    re.MULTILINE,
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
    # Compile each name's reference pattern once per call rather than
    # once per (segment × name) pair. A run: block with 200 segments
    # and 5 secret env vars is the difference between 5 compiles and
    # 1000.
    name_refs = [
        re.compile(rf"\${{{name}}}|\$\b{re.escape(name)}\b")
        for name in secret_env_names
    ]
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
            for ref in name_refs:
                if ref.search(seg):
                    return True
    return False


def _shell_trace_with_secret_ref(
    run: str, secret_env_names: set[str],
) -> bool:
    """Return True when *run* enables shell trace AND references any
    secret-bound env var.

    Shell trace (``set -x`` / ``set -o xtrace``) dumps each command
    with arguments expanded before execution. A secret-bound variable
    referenced anywhere in the body after the trace toggle lands in
    the log verbatim. The toggle position within the script doesn't
    affect detection here, the rule is concerned with the LEAK not
    with proving order of execution.
    """
    if not secret_env_names:
        return False
    if not _SHELL_TRACE_RE.search(run):
        return False
    for name in secret_env_names:
        if re.search(rf"\${{{name}\b|\${re.escape(name)}\b", run):
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
                continue
            if _shell_trace_with_secret_ref(run, secret_env):
                offenders.append(f"{job_id}[{idx}] (set -x + secret env)")
    passed = not offenders
    desc = (
        "No ``run:`` block prints a secret value to the build log."
        if passed else
        f"{len(offenders)} ``run:`` block(s) print secret values to "
        f"the build log: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Log redaction is "
        f"best-effort, substrings, base64-encoded copies, and "
        f"partial echoes evade it, and API log readers see the raw "
        f"stream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
