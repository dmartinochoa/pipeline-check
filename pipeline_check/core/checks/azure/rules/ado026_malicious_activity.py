"""ADO-026, pipeline contains evidence of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns, summarize_malicious_hits
from ..._primitives.blob_rule import yaml_blob_check
from ...base import Severity
from ...rule import Rule

RULE = Rule(
    id="ADO-026",
    title="Pipeline contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify the PR/branch that "
        "added the matching task(s), rotate any Service Connections the "
        "pipeline can reach, and audit Pipeline run logs for outbound "
        "traffic to the matched hosts."
    ),
    docs_note=(
        "ADO pipelines can run arbitrary shell via ``bash`` / "
        "``script`` / ``powershell`` tasks. This rule scans every "
        "string value for known-bad patterns (reverse shells, "
        "base64-decoded execution, miner binaries, exfil channels). "
        "Orthogonal to ADO-016/ADO-017/ADO-023."
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
)


check = yaml_blob_check(
    RULE,
    scanner=find_malicious_patterns,
    pass_desc="No indicators of malicious activity detected.",
    fail_desc=summarize_malicious_hits,
    pass_recommendation="No action required.",
)
