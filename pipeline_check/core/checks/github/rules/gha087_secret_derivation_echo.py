"""GHA-087. Derived-value of a secret printed to the build log.

cicd-goat scenario 27 (CICD-SEC-10): GitHub's log redaction matches
*exact* registered secret values. Any derived form (a SHA-256
fingerprint, the first 8 characters via ``${VAR:0:8}``, a base64
wrapper, a ``cut -c1-8`` truncation) is a different string from the
registered value, so the masker doesn't redact it.

Public-repo workflow logs are world-readable and indexed by search
engines. An 8-char prefix is enough to fingerprint which provider
the secret came from (``ghp_``, ``ghs_``, ``xoxb-``, ``AKIA``, ...)
and which org owns it. The SHA-256 fingerprint acts as a stable
identifier across leaks; an attacker can confirm "this leaked
secret here is the same as the one rotated in that other org" even
without recovering the plaintext.

GHA-033 already catches the ``set -x`` shape (every command echoed
verbatim) and direct ``echo $SECRET`` / ``echo "${{ secrets.X }}"``
shapes. GHA-087 covers the *derived* value half: a transform is
applied to the secret-bound variable AND the transformed result
reaches a print sink on the same logical line.

The rule is single-line-scoped on purpose. A workflow that assigns
the transformed value to a variable on one line and prints it on
another line (a two-step leak) needs multi-line dataflow that
TAINT-001 already provides for the secret-source shape; layering
the derivation on top of that is a separate, larger rule.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-087",
    title="Derived value of a secret printed to the build log",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10", "CICD-SEC-6"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Never print anything derived from a secret. Not the "
        "SHA-256, not the first eight characters, not the base64 "
        "wrapper, not the length. GitHub's log redaction only "
        "matches the exact registered secret value, every "
        "derived form lands in the (world-readable) log "
        "unmasked. If you genuinely need to compare secrets across "
        "runs, do the comparison inside a step and report a "
        "boolean (``[ -n \"$X\" ] && echo set || echo unset``). "
        "If you need to confirm rotation worked, run the "
        "downstream check against the secret rather than echo a "
        "fingerprint."
    ),
    docs_note=(
        "Fires on a single ``run:`` line that combines all three "
        "of the following:\n\n"
        "1. A reference to a secret, either a ``${{ secrets.* }}`` "
        "context expression or a ``$NAME`` / ``${NAME}`` expansion "
        "of a step ``env:`` value bound to ``secrets.*``.\n"
        "2. A transform applied to that reference:\n"
        "   * **Hash:** ``sha256sum``, ``sha1sum``, ``md5sum``, "
        "``sha512sum``, ``shasum``, ``openssl dgst``.\n"
        "   * **Encoding:** ``base64``, ``base32``.\n"
        "   * **Truncation:** ``cut -c<n>``, ``head -c<n>``.\n"
        "   * **Bash parameter expansion:** ``${VAR:0:N}``, "
        "``${VAR::N}``, ``${VAR:N:M}`` (substring slice).\n"
        "3. A print sink on the same line: ``echo`` / ``printf`` "
        "/ ``tee`` at the head, or a redirect to "
        "``$GITHUB_OUTPUT`` / ``$GITHUB_STEP_SUMMARY`` / an "
        "ordinary file.\n\n"
        "Pairs with GHA-033 (which covers ``set -x`` shell-trace "
        "leaks and direct ``echo ${{ secrets.X }}`` shapes). The "
        "two rules are deliberately disjoint: a step that hits "
        "both shapes fires both findings rather than one. Out of "
        "scope (deliberate carve-out): multi-line shape where "
        "the transformation lands in an intermediate variable on "
        "one line and the variable is printed on another. "
        "Detecting that needs cross-line dataflow; the "
        "single-line scope captures the canonical foot-guns from "
        "the field without over-firing on legitimate "
        "verification-then-discard patterns."
    ),
    known_fp=(
        "Steps that explicitly want a non-reversible secret "
        "fingerprint for cross-run identification (rare; the "
        "rotation-status use case is the only legitimate one). "
        "Suppress per-step via ignore-file when the operator has "
        "audited that the entropy of the secret makes the "
        "fingerprint genuinely unguessable. A boolean ``set / "
        "unset`` print is always safer and is what the "
        "recommendation steers toward.",
    ),
    incident_refs=(
        "OWASP CICD-SEC-10 (Insufficient Logging and Visibility): "
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-10-Insufficient-Logging-and-Visibility",
    ),
    exploit_example=(
        "# Vulnerable: ``${TOKEN:0:8}`` is an 8-char prefix of the\n"
        "# secret. GitHub's masker registers ``TOKEN`` to redact\n"
        "# the *full* value; the truncated substring is a different\n"
        "# string and lands in the log verbatim. An 8-char prefix\n"
        "# of ``ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`` reveals\n"
        "# the issuer and is enough to fingerprint the org across\n"
        "# any leaked log.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TOKEN: ${{ secrets.DEPLOY_KEY }}\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo \"token prefix: ${TOKEN:0:8}\"\n"
        "          echo \"fingerprint=$(echo $TOKEN | sha256sum | "
        "cut -c1-16)\" >> \"$GITHUB_OUTPUT\"\n"
        "\n"
        "# Safe: report a boolean. The downstream step that needs\n"
        "# the secret can confirm it works against the live API\n"
        "# rather than the workflow echo'ing a derived form.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      TOKEN: ${{ secrets.DEPLOY_KEY }}\n"
        "    steps:\n"
        "      - run: |\n"
        "          [ -n \"$TOKEN\" ] && echo \"deploy key set\" "
        "|| echo \"deploy key missing\""
    ),
)


#: Transform shapes: command names that fingerprint, encode, or
#: truncate. The hash / encode commands keep both word boundaries so
#: ``sha256sumX`` doesn't false-match; the ``cut -c1-8`` / ``head -c12``
#: short forms have no trailing word boundary because ``-c`` runs
#: directly into the count.
_TRANSFORM_RE = re.compile(
    r"\b(?:sha(?:1|256|384|512)?sum"
    r"|shasum"
    r"|md5sum"
    r"|base(?:64|32)"
    r"|openssl\s+dgst"
    r")\b"
    r"|\bcut\s+-c"
    r"|\bhead\s+-c",
)

#: Bash parameter-expansion truncation: ``${VAR:0:N}``, ``${VAR::N}``,
#: ``${VAR:N:M}``. The first capture is the variable name. ``${VAR}``
#: alone (no slice) is the standard env reference and is NOT a
#: transform.
_PARAM_TRUNC_RE = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-?\d+|::-?\d+|:-?\d+:-?\d+)\}",
)

#: Print sinks on a logical line. ``echo`` / ``printf`` / ``tee`` at
#: the head of a segment, or a redirect to a logged target.
_SINK_RE = re.compile(
    r"(?:^|[\s;&|])(?:echo|printf|tee)\b"
    r"|>>?\s*\$\{?GITHUB_(?:OUTPUT|STEP_SUMMARY)\b"
    r"|>>?\s*[^\s&|;<>]+",
)

#: Direct ``${{ secrets.<name> }}`` context expression in a body.
_SECRET_CTX_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z_]\w*\s*\}\}")


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


def _line_has_secret_ref(line: str, secret_names: set[str]) -> bool:
    """True when *line* references a secret context or a secret-bound env."""
    if _SECRET_CTX_RE.search(line):
        return True
    for name in secret_names:
        # ``$NAME`` (with word boundary) or ``${NAME...}`` (allowing
        # parameter expansion to follow). Word boundary on plain
        # ``$NAME`` keeps ``$TOKEN_PATH`` from matching ``TOKEN``.
        if re.search(
            rf"\$(?:\{{{re.escape(name)}\b|{re.escape(name)}\b)",
            line,
        ):
            return True
    return False


def _line_has_transform_on_secret(
    line: str, secret_names: set[str],
) -> bool:
    """True when a fingerprint / encode / truncate transform appears on
    *line* alongside a secret reference, OR a bash param-expansion
    slice (``${VAR:0:N}``) targets a secret-bound var.
    """
    # Bash param-expansion truncation is by itself an explicit
    # transform on a named variable. Check the slice match's name
    # against the secret-bound set.
    for m in _PARAM_TRUNC_RE.finditer(line):
        if m.group("name") in secret_names:
            return True
    # Pipe / here-string / arg-position transform commands. Confirm
    # *some* secret reference appears on the same line (otherwise a
    # legitimate ``echo "$(date | sha256sum)" >> ...`` doesn't fire).
    if _TRANSFORM_RE.search(line):
        if _line_has_secret_ref(line, secret_names):
            return True
    return False


def _line_has_sink(line: str) -> bool:
    """True when *line* prints / writes to a logged sink."""
    return bool(_SINK_RE.search(line))


def _scan_run_body(run: str, secret_names: set[str]) -> list[str]:
    """Return the offending lines, joined by line-segment so each
    finding entry points at a single shell pipeline.

    A line counts when all three conjuncts hold: secret ref +
    transform on that secret + print sink.
    """
    offenders: list[str] = []
    for raw_line in run.splitlines():
        for segment in re.split(r"(?:&&|\|\||;)", raw_line):
            seg = segment.strip()
            if not seg:
                continue
            if not _line_has_transform_on_secret(seg, secret_names):
                continue
            if not _line_has_sink(seg):
                continue
            offenders.append(seg)
    return offenders


def check(path: str, doc: dict[str, Any]) -> Finding:
    leaks: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            secret_names = _step_secret_env_vars(step)
            # Even with no env-bound secret, the body might splice
            # ``${{ secrets.* }}`` directly. ``_scan_run_body`` only
            # fires when a transform-on-secret + sink combination
            # is present; an empty ``secret_names`` is fine because
            # the body-side ``${{ secrets.* }}`` regex covers it.
            for offender in _scan_run_body(run, secret_names):
                preview = offender if len(offender) <= 80 else offender[:77] + "..."
                leaks.append(f"{job_id}[{idx}]: {preview}")
    passed = not leaks
    desc = (
        "No ``run:`` block prints a derived value of a secret."
        if passed else
        f"{len(leaks)} ``run:`` line(s) print a derived value of a "
        f"secret to a logged sink: "
        f"{'; '.join(leaks[:3])}"
        f"{'...' if len(leaks) > 3 else ''}. GitHub's secret masker "
        f"only matches exact registered values; SHA-256 / base64 / "
        f"first-N-chars all slip through."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
