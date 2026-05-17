"""DF-026, ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` (Node TLS verify off)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-026",
    title="ENV disables Node.js TLS certificate verification",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-295", "CWE-319"),
    recommendation=(
        "Remove the ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` "
        "instruction. The variable tells Node's TLS layer to "
        "accept any certificate the upstream presents — "
        "self-signed, expired, hostname-mismatched, attacker-"
        "presented. Anything baked into ``ENV`` applies to every "
        "Node process the image ever launches: ``npm install``, "
        "``npm publish``, runtime fetch calls, postinstall "
        "scripts. The attacker doesn't need to compromise the "
        "registry — they only need to MITM the network path "
        "between the container and any HTTPS endpoint.\n\n"
        "If the internal registry / API genuinely has a self-"
        "signed cert, install the CA into the image's truststore "
        "instead: ``COPY ca.crt /usr/local/share/ca-certificates/`` "
        "+ ``RUN update-ca-certificates`` (Debian) or "
        "``RUN cat ca.crt >> /etc/ssl/certs/ca-certificates.crt`` "
        "(Alpine). The CA install is a one-time build cost; the "
        "bypass is a permanent runtime liability."
    ),
    docs_note=(
        "Fires on any ``ENV NODE_TLS_REJECT_UNAUTHORIZED=`` value "
        "that resolves to ``0`` (or the string ``\"0\"``). The "
        "documented Node.js mechanism for disabling TLS "
        "verification, applies to every TLS socket the runtime "
        "opens for the rest of the image's life. ``ENV ... =1`` "
        "(re-enable) and ``ENV ... =`` (clear) pass. The same "
        "primitive shows up in npm postinstall logs whenever a "
        "dep tries to fetch over a network the runner can't "
        "verify; once the env is set, the failure mode that "
        "caught the bad cert is gone."
    ),
    known_fp=(
        "Test-only images that interact with a local mock server "
        "using a throwaway self-signed cert sometimes set this "
        "intentionally. Keep the bypass scoped to a separate "
        "``test`` build stage and DON'T copy it into the final "
        "image; the production stage should never carry the "
        "variable. Suppress on the test-stage Dockerfile with "
        "a rationale that names the mock server.",
    ),
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "NODE_TLS_REJECT_UNAUTHORIZED":
            continue
        # Value of ``0`` (or string ``"0"``) is the disable signal.
        # Empty / ``1`` / unset all pass.
        stripped = value.strip() if isinstance(value, str) else ""
        if stripped != "0":
            continue
        offenders.append(f"L{line_no}: ENV {key}={value}")
    passed = not offenders
    desc = (
        "No ``ENV`` directive disables Node.js TLS verification."
        if passed else
        f"{len(offenders)} ``ENV`` directive(s) disable Node.js "
        f"TLS verification: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every Node "
        f"process the image launches accepts any certificate "
        f"the upstream presents."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
