"""PULUMI-003. Pulumi source file embeds a hardcoded credential."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PulumiContext

RULE = Rule(
    id="PULUMI-003",
    title="Pulumi source file embeds a hardcoded credential",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-312"),
    recommendation=(
        "Remove every hardcoded credential literal and load the "
        "value via Pulumi's secret-backed config instead. The two "
        "canonical patterns are:\n\n"
        "* ``new pulumi.Config().requireSecret(\"<key>\")`` "
        "(TypeScript) / ``Config().require_secret(\"<key>\")`` "
        "(Python). Reads from the stack's encrypted config table.\n"
        "* For credentials that already live in a cloud secret "
        "manager, read them via the language's native cloud SDK "
        "and pass the resulting ``pulumi.Output`` into resource "
        "args. Pulumi propagates the secret marker through "
        "outputs so downstream stack outputs are also marked "
        "encrypted.\n\n"
        "After the swap, rotate every credential that ever lived "
        "in the source file, even briefly. Anything committed to "
        "git stays in clones, backups, and CI caches "
        "indefinitely; the rotation is what closes the gap, the "
        "code change alone doesn't."
    ),
    docs_note=(
        "Scans every source file in the Pulumi project root for "
        "high-confidence credential shapes:\n\n"
        "* ``AKIA[0-9A-Z]{16}`` / ``ASIA[0-9A-Z]{16}`` — AWS "
        "access key prefixes\n"
        "* ``AIza[0-9A-Za-z_-]{35}`` — Google API keys\n"
        "* ``ghp_[A-Za-z0-9]{36}`` / ``github_pat_[A-Za-z0-9_]{82}`` "
        "— GitHub personal-access tokens\n"
        "* ``-----BEGIN [A-Z ]*PRIVATE KEY-----`` — PEM-style "
        "private key blocks (RSA / EC / OPENSSH / PGP)\n\n"
        "Each pattern matches the canonical wire format so the "
        "false-positive surface is small. Test / fixture files "
        "with deliberate-fake credentials (``AKIAIOSFODNN7EXAMPLE``) "
        "are the main exemption class; suppress per file with a "
        "one-line rationale.\n\n"
        "Skips files outside the Pulumi project root (vendored "
        "deps, ``node_modules``, ``.venv``)."
    ),
    known_fp=(
        "Documentation / example files that deliberately include "
        "credentials in their canonical-fake form trip the rule "
        "by shape (``AKIAIOSFODNN7EXAMPLE`` is intentionally on "
        "AWS's docs catalog). Suppress those files explicitly.",
    ),
    incident_refs=(
        "Long-running pattern in Pulumi repos that begin life as "
        "a single-file ``index.ts`` with a quickly-pasted AWS "
        "access key for early bootstrapping. The key is then "
        "supposed to be replaced before commit; the replacement "
        "is forgotten; the repo goes public weeks later, and the "
        "key — still active — gets harvested by an opportunistic "
        "scanner within hours.",
    ),
    exploit_example=(
        "# Vulnerable: literal AWS access key in source.\n"
        "# index.ts\n"
        "const provider = new aws.Provider(\"prod\", {\n"
        "    region: \"us-east-1\",\n"
        "    accessKey: \"AKIAIOSFODNN7EXAMPLE\",\n"
        "    secretKey: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\n"
        "});\n"
        "\n"
        "# Attack: ``git push`` lands the file on the default\n"
        "# branch. A drive-by scanner (Trufflehog / GitHub's own\n"
        "# secret-scanning) finds the AKIA pattern within minutes;\n"
        "# the AWS key is used to enumerate IAM, then escalate.\n"
        "# Detection time is rarely fast enough to beat the\n"
        "# exfiltration window.\n"
        "\n"
        "# Safe: load credentials from the stack's encrypted\n"
        "# config table.\n"
        "# index.ts\n"
        "const cfg = new pulumi.Config();\n"
        "const provider = new aws.Provider(\"prod\", {\n"
        "    region: \"us-east-1\",\n"
        "    accessKey: cfg.requireSecret(\"awsAccessKey\"),\n"
        "    secretKey: cfg.requireSecret(\"awsSecretKey\"),\n"
        "});\n"
        "\n"
        "# Stack file:\n"
        "# $ pulumi config set --secret awsAccessKey AKIA...\n"
        "# $ pulumi config set --secret awsSecretKey wJal...\n"
        "# Plaintext keys never land in source."
    ),
)


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("gcp-api-key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github-pat",
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("private-key-block",
     re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
)


def check(ctx: PulumiContext) -> Finding:
    if not ctx.sources:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=(
                ctx.projects[0].path if ctx.projects else "Pulumi.yaml"
            ),
            description=(
                "No source files in the Pulumi project; nothing to "
                "audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for source in ctx.sources:
        for label, pattern in _PATTERNS:
            m = pattern.search(source.text)
            if not m:
                continue
            line_no = source.text[:m.start()].count("\n") + 1
            offenders.append(f"{label} in {source.path}:{line_no}")
            locations.append(Location(
                path=source.path,
                start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        f"No hardcoded credential literals across "
        f"{len(ctx.sources)} source file(s)."
        if passed else
        f"{len(offenders)} hardcoded credential literal(s) "
        f"detected: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Rotate every "
        f"affected credential after removing the literal; the "
        f"value persists in git clones indefinitely."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=(
            locations[0].path if locations
            else (ctx.projects[0].path if ctx.projects else "Pulumi.yaml")
        ),
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
