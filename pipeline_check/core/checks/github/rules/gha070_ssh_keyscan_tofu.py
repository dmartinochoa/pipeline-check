"""GHA-070. ``ssh-keyscan`` / disabled host-key checks trust-on-first-use.

zizmor proposal #2012 (``ssh-keyscan``). The two canonical shapes:

  ssh-keyscan github.com >> ~/.ssh/known_hosts
  ssh -o StrictHostKeyChecking=no <host> ...
  ssh -o UserKnownHostsFile=/dev/null <host> ...
  rsync -e "ssh -o StrictHostKeyChecking=no" ...
  scp -o StrictHostKeyChecking=no ...

All four accept whatever host key the network returns. On a
workflow-runner that's been compromised (or where DNS got poisoned
in front of a self-hosted runner) the runner mints a fresh
known_hosts entry against the attacker's MITM key and proceeds to
trust it for every subsequent ``git fetch`` / ``scp`` / ``rsync``
from the same job.

The fix is to ship a pinned ``known_hosts`` with the
runner-provisioning recipe and never call ``ssh-keyscan`` from a
workflow. GitHub provides published host keys
(https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
that you can hard-pin into the action's known_hosts setup.
"""
from __future__ import annotations

import re
from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-070",
    title="``ssh-keyscan`` / disabled host-key check trust-on-first-use",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-322",),  # Key Exchange without Entity Authentication
    recommendation=(
        "Pin the SSH host keys explicitly. For GitHub's "
        "``github.com`` host, ship the published fingerprints "
        "(see ``github.com/.well-known/ssh-fingerprints``) in a "
        "``known_hosts`` file that the workflow installs. Never "
        "call ``ssh-keyscan`` from a workflow, every invocation "
        "is trust-on-first-use against whatever the network "
        "returns. Same applies to ``StrictHostKeyChecking=no`` / "
        "``UserKnownHostsFile=/dev/null`` on ``ssh`` / ``scp`` / "
        "``rsync``, those flags accept any host key the first "
        "(and every subsequent) connection presents."
    ),
    docs_note=(
        "Fires on any ``run:`` body containing one of:\n\n"
        "* ``ssh-keyscan ... >> <known_hosts>`` (or ``>`` for "
        "overwrite).\n"
        "* ``-o StrictHostKeyChecking=no`` (single or double "
        "quoted) on ``ssh`` / ``scp`` / ``rsync`` / ``sftp``.\n"
        "* ``-o UserKnownHostsFile=/dev/null`` (the inverse "
        "shape: don't persist any host key check).\n"
        "* ``-o StrictHostKeyChecking=accept-new`` (TOFU mode, "
        "accepts the first key seen).\n\n"
        "The rule pairs with GHA-023 (TLS / cert verify bypass) "
        "on the HTTPS side and with GHA-054 (checkout SSH-key "
        "persistence) on the credentials side. All three describe "
        "the same threat shape: turning off authentication "
        "primitives that defend against MITM on a runner whose "
        "network the workflow doesn't fully control."
    ),
    known_fp=(
        "First-time bootstrap of a self-hosted runner where the "
        "runner image's host-key store is intentionally empty and "
        "ssh-keyscan is the bootstrap step. Suppress per-step via "
        "ignore-file when the bootstrap step is bounded by a "
        "post-bootstrap key-validation check (compare the "
        "ingested key against a known-good fingerprint stored in "
        "a secret). Without that follow-up validation the "
        "suppression isn't safe.",
    ),
    incident_refs=(
        "zizmor proposal #2012 (ssh-keyscan audit): "
        "https://github.com/zizmorcore/zizmor/issues/2012",
        "GitHub Docs - SSH key fingerprints: "
        "https://docs.github.com/en/authentication/keeping-"
        "your-account-and-data-secure/githubs-ssh-key-fingerprints",
    ),
    exploit_example=(
        "# Vulnerable: ssh-keyscan accepts whatever the network\n"
        "# returns. A self-hosted runner on a compromised LAN, or\n"
        "# a GitHub-hosted runner with a DNS-spoofed upstream,\n"
        "# silently mints a malicious host-key entry that every\n"
        "# later git/ssh/rsync call from the same job trusts.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          mkdir -p ~/.ssh\n"
        "          ssh-keyscan github.com >> ~/.ssh/known_hosts\n"
        "          git fetch git@github.com:org/repo.git\n"
        "\n"
        "# Safe: ship a pinned known_hosts file with the workflow.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: |\n"
        "          mkdir -p ~/.ssh\n"
        "          cp .github/ssh/github_known_hosts ~/.ssh/known_hosts\n"
        "          chmod 600 ~/.ssh/known_hosts\n"
        "          git fetch git@github.com:org/repo.git"
    ),
)


#: Capture group is the offending substring used in the description.
_SSH_KEYSCAN_RE = re.compile(
    r"\bssh-keyscan\b[^\n]*?(?:>>?|\|)",
)

#: ``StrictHostKeyChecking=no`` / ``=accept-new`` and the inverse
#: ``UserKnownHostsFile=/dev/null`` family. Both single and double
#: quoted argument forms; values with optional surrounding spaces.
_HOST_KEY_BYPASS_RE = re.compile(
    r"StrictHostKeyChecking\s*=\s*(?:no|accept-new)\b"
    r"|UserKnownHostsFile\s*=\s*/dev/null\b",
    re.IGNORECASE,
)


def _scan_run(run: str) -> list[str]:
    """Return offender substrings from *run* body."""
    out: list[str] = []
    for _m in _SSH_KEYSCAN_RE.finditer(run):
        out.append("ssh-keyscan >> known_hosts")
        break  # one mention per run-body is enough; many TOFU lines collapse
    for m in _HOST_KEY_BYPASS_RE.finditer(run):
        out.append(m.group(0))
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            offenders_here = _scan_run(run)
            if not offenders_here:
                continue
            offenders.append(
                f"{job_id}[{idx}]: {', '.join(offenders_here[:2])}"
            )
            line = _line_of(step)
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
    passed = not offenders
    desc = (
        "No SSH trust-on-first-use shape in any ``run:`` body."
        if passed else
        f"{len(offenders)} step(s) accept arbitrary SSH host keys: "
        f"{'; '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}. The runner's "
        f"upstream network can MITM every subsequent SSH / "
        f"git-over-SSH / scp / rsync call from the same job."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
