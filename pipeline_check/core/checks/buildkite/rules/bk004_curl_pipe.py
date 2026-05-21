"""BK-004, ``curl <url> | sh`` and equivalents in step commands."""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-004",
    title="Remote script piped into shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-1"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Download the installer to disk, verify a checksum or "
        "signature, then execute it. ``curl ... | sh`` lets the "
        "remote host change what runs in your pipeline at any time, "
        "and any TLS / DNS error during download silently feeds a "
        "partial script to the shell."
    ),
    docs_note=(
        "Uses the cross-provider ``_primitives.remote_script_exec`` "
        "detector shared with GHA-016 / GL-016 / GCB-010 / DF-004 / "
        "ARGO-008 / TKN-008. Catches ``curl|bash``, ``curl|sh``, "
        "``wget|bash``, ``bash -c \"$(curl …)\"``, ``python -c "
        "urllib.urlopen``, ``curl > x.sh && bash x.sh``, and the "
        "PowerShell ``irm | iex`` variants. Use ``curl -fsSLO "
        "<url>; sha256sum -c install.sh.sha256; bash install.sh`` "
        "instead."
    ),
    exploit_example=(
        "# Vulnerable: ``curl | bash`` trusts both the network path\n"
        "# (any MITM substitutes the script) and the host (a\n"
        "# compromised installer endpoint silently serves attacker\n"
        "# code). The script runs in the build's shell context.\n"
        "steps:\n"
        "  - label: \":hammer: install tools\"\n"
        "    command: |\n"
        "      curl -fsSL https://installer.example.com/cli.sh | bash\n"
        "      ./cli build\n"
        "\n"
        "# Safe: download to a file, verify a sha256 digest from a\n"
        "# trusted source, then execute. If the upstream content\n"
        "# changes the digest stops matching and the build fails\n"
        "# before the malicious code runs.\n"
        "steps:\n"
        "  - label: \":hammer: install tools\"\n"
        "    command: |\n"
        "      curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh\n"
        "      echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -\n"
        "      bash /tmp/cli.sh\n"
        "      ./cli build"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            hits = remote_script_exec.scan(cmd)
            if hits:
                offenders.append(
                    f"{step_label(step, idx)}: {hits[0].snippet[:80]}"
                )
                break
    passed = not offenders
    desc = (
        "No curl-pipe-shell idioms in step commands."
        if passed else
        f"{len(offenders)} step(s) pipe a remote script into a shell: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Download, verify, then "
        f"execute."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
