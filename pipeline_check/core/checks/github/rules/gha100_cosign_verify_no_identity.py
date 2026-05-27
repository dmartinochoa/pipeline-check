"""GHA-100. ``cosign verify`` without ``--certificate-identity`` binding.

Keyless Sigstore verification (``cosign verify`` / ``cosign verify-blob``)
requires two flags to bind the signer's identity:

  * ``--certificate-identity`` (or ``--certificate-identity-regexp``)
  * ``--certificate-oidc-issuer`` (or ``--certificate-oidc-issuer-regexp``)

When either flag is missing, ``cosign verify`` accepts any valid
Sigstore signature. An attacker who replaces the artifact on the CDN
(or in a registry) can mint their own valid signature from their own
GitHub workflow, the verification step passes, and the runner executes
attacker-controlled code.

The pattern is common in "verify-then-deploy" pipelines that adopted
keyless signing but skipped the identity binding step. Before cosign
v2.0 the flags didn't exist; many tutorials still omit them.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-100",
    title="``cosign verify`` without certificate identity binding",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-D-INTEGRITY",),
    cwe=("CWE-345",),
    recommendation=(
        "Add both ``--certificate-identity`` (or "
        "``--certificate-identity-regexp``) AND "
        "``--certificate-oidc-issuer`` (or "
        "``--certificate-oidc-issuer-regexp``) to every ``cosign "
        "verify`` / ``cosign verify-blob`` invocation. Pin the "
        "identity to the expected build pipeline's workflow ref and "
        "the issuer to ``https://token.actions.githubusercontent.com`` "
        "(for GitHub Actions OIDC). Without both flags, any Sigstore "
        "signer's certificate satisfies the verification."
    ),
    docs_note=(
        "Scans ``run:`` blocks for ``cosign verify`` and "
        "``cosign verify-blob`` invocations. Flags when either "
        "``--certificate-identity`` / ``--certificate-identity-regexp`` "
        "or ``--certificate-oidc-issuer`` / "
        "``--certificate-oidc-issuer-regexp`` is absent from the "
        "command line.\n\n"
        "The ``cosign verify-attestation`` subcommand is also checked "
        "because it shares the same identity-binding requirement.\n\n"
        "Multi-line ``run:`` blocks (``|`` / ``>`` YAML scalars) are "
        "handled by scanning the full scalar value. Backslash "
        "continuations are collapsed before matching so a split "
        "invocation like ``cosign verify \\\\\\n  --key ...`` is "
        "still detected.\n\n"
        "This rule is the consumer-side complement of GHA-006 (missing "
        "artifact signing) and GHA-024 (missing SLSA provenance). "
        "GHA-100 catches the case where signing exists but the "
        "verification step doesn't bind the signer's identity."
    ),
    known_fp=(
        "Key-based verification (``--key``) doesn't use "
        "certificate identity flags. The rule checks for ``--key`` "
        "and suppresses the finding when present.",
    ),
    incident_refs=(
        "https://docs.sigstore.dev/cosign/verifying/verify/",
        "https://blog.sigstore.dev/cosign-2-0-released/",
    ),
    exploit_example=(
        "# Vulnerable: cosign verify without identity binding.\n"
        "# Any valid Sigstore signature satisfies the check.\n"
        "jobs:\n"
        "  verify-and-deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: cosign verify ghcr.io/org/app:latest\n"
        "      - run: docker run ghcr.io/org/app:latest\n"
        "\n"
        "# Safe: pin certificate identity + OIDC issuer.\n"
        "jobs:\n"
        "  verify-and-deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          cosign verify ghcr.io/org/app:latest \\\n"
        "            --certificate-identity-regexp 'https://github.com/org/app/.*' \\\n"
        "            --certificate-oidc-issuer https://token.actions.githubusercontent.com\n"
        "      - run: docker run ghcr.io/org/app:latest"
    ),
)

_COSIGN_VERIFY_RE = re.compile(
    r"\bcosign\s+(?:verify|verify-blob|verify-attestation)\b"
)

_CERT_IDENTITY_RE = re.compile(
    r"--certificate-identity(?:-regexp)?\b"
)

_OIDC_ISSUER_RE = re.compile(
    r"--certificate-oidc-issuer(?:-regexp)?\b"
)

_KEY_FLAG_RE = re.compile(r"--key\b")


def _collapse_continuations(text: str) -> str:
    return re.sub(r"\\\s*\n\s*", " ", text)


def _check_run_block(run: str) -> list[str]:
    """Return missing-flag labels for each cosign verify invocation."""
    run = _collapse_continuations(run)
    issues: list[str] = []
    for m in _COSIGN_VERIFY_RE.finditer(run):
        start = m.start()
        end_of_line = run.find("\n", start)
        if end_of_line == -1:
            end_of_line = len(run)
        next_cmd = run.find(";", start, end_of_line)
        pipe = run.find("|", start, end_of_line)
        and_op = run.find("&&", start, end_of_line)
        or_op = run.find("||", start, end_of_line)
        bounds = [end_of_line]
        for b in (next_cmd, pipe, and_op, or_op):
            if b != -1:
                bounds.append(b)
        segment = run[start:min(bounds)]

        if _KEY_FLAG_RE.search(segment):
            continue

        missing: list[str] = []
        if not _CERT_IDENTITY_RE.search(segment):
            missing.append("--certificate-identity(-regexp)")
        if not _OIDC_ISSUER_RE.search(segment):
            missing.append("--certificate-oidc-issuer(-regexp)")
        if missing:
            cmd = m.group(0).strip()
            issues.append(f"``{cmd}`` missing {', '.join(missing)}")
    return issues


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations = []

    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            issues = _check_run_block(run)
            if issues:
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                for issue in issues:
                    offenders.append(f"{job_id}.{name}: {issue}")
                locations.append(step_location(path, step))

    passed = not offenders
    if passed:
        desc = (
            "No ``cosign verify`` invocation is missing certificate "
            "identity binding."
        )
    else:
        desc = (
            f"{len(offenders)} ``cosign verify`` invocation(s) lack "
            f"certificate identity binding: "
            f"{'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. "
            f"Without ``--certificate-identity`` and "
            f"``--certificate-oidc-issuer``, any valid Sigstore "
            f"signature satisfies the verification."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
