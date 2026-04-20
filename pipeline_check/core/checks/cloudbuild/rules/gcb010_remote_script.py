"""GCB-010 — remote script piped to shell interpreter.

Cloud Build steps that run ``curl <url> | bash`` (or the wget,
python, perl, ruby, or PowerShell equivalents) execute
attacker-controllable content the moment the URL's host is
compromised or DNS/CDN is poisoned. Reuses the cross-provider
``_primitives.remote_script_exec`` detector so the idiom catalogue
stays aligned with GHA-016 / GL-016 / BB-012 / ADO-016 / CC-016 /
JF-016.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GCB-010",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository and "
        "invoke it from the checkout — removing the network fetch "
        "removes the attacker-controllable content entirely."
    ),
    docs_note=(
        "Detects ``curl | bash``, ``wget | sh``, ``bash -c \"$(curl …)\"``, "
        "inline ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, "
        "and PowerShell ``irm | iex`` idioms. Vendor-trusted hosts "
        "(rustup.rs, get.docker.com, sdk.cloud.google.com, …) are still "
        "flagged at HIGH but the hit carries a ``vendor_trusted`` marker "
        "so dashboards can stratify known-vendor installers from arbitrary "
        "attacker URLs."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = remote_script_exec.scan(blob_lower(doc))
    passed = not hits
    desc = (
        "No curl-pipe / wget-pipe / python-urlopen patterns detected."
        if passed else
        f"{len(hits)} remote-script-to-interpreter pattern(s) detected: "
        f"{', '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
