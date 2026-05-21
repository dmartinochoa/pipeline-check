"""CC-016, remote script piped to shell interpreter."""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity, blob_lower
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands

RULE = Rule(
    id="CC-016",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository."
    ),
    docs_note=(
        "Detects `curl | bash`, `wget | sh`, and similar patterns "
        "that pipe remote content directly into a shell interpreter "
        "inside a CircleCI config. An attacker who controls the remote "
        "endpoint (or poisons DNS / CDN) gains arbitrary code "
        "execution in the CI runner."
    ),
    known_fp=(
        "Established vendor installers (get.docker.com, sh.rustup.rs, "
        "bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) "
        "ship via HTTPS from their own CDN and are idiomatic. This "
        "rule defaults to LOW confidence so CI gates can ignore them "
        "with --min-confidence MEDIUM; the finding still surfaces so "
        "teams that want cryptographic verification can audit.",
    ),
    exploit_example=(
        "# Vulnerable: ``curl | bash`` install one-liner trusts\n"
        "# both the network path and the installer host. A MITM\n"
        "# or compromised endpoint ships malicious code into the\n"
        "# step's shell with the job's full credential set.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  install-tools:\n"
        "    docker:\n"
        "      - image: cimg/base@sha256:abc123...\n"
        "    steps:\n"
        "      - run: curl -fsSL https://installer.example.com/cli.sh | bash\n"
        "\n"
        "# Safe: download to a file, verify a sha256 digest from\n"
        "# a trusted source, then execute.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  install-tools:\n"
        "    docker:\n"
        "      - image: cimg/base@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          set -e\n"
        "          curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh\n"
        "          echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -\n"
        "          bash /tmp/cli.sh"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Document-level blob scan, keeps the legacy detection surface
    # so a curl-pipe in a top-level command alias or a parameter
    # default still trips the rule.
    hits = remote_script_exec.scan(blob_lower(doc))

    # Per-job rescan to recover the offending job's line. Each
    # CircleCI job has a ``steps:`` list whose ``run:`` commands
    # are the typical home of curl-pipe idioms.
    locations: list[Location] = []
    for _, job in iter_jobs(doc):
        if any(remote_script_exec.scan(cmd) for cmd in iter_run_commands(job)):
            line = _line_of(job)
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))

    passed = not hits
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this config."
        if passed else
        f"Remote script piped to interpreter detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
