"""DF-030, ``ENV NODE_OPTIONS`` carries ``--require`` or ``--inspect``."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-030",
    title="ENV NODE_OPTIONS preloads code or opens an inspector",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-94", "CWE-489"),
    recommendation=(
        "Drop the ``--require=`` / ``--import=`` and "
        "``--inspect`` / ``--inspect-brk`` flags from "
        "``NODE_OPTIONS``. Each is a runtime-injection or "
        "remote-debugger primitive baked into every ``node`` "
        "invocation the image runs:\n\n"
        "* ``--require=<module>`` and ``--import=<module>`` "
        "  preload a module before user code runs. The Node "
        "  equivalent of ``LD_PRELOAD`` (DF-023): any process "
        "  that can drop a file in the image's filesystem can "
        "  inject that module's side effects into every Node "
        "  process.\n"
        "* ``--inspect`` / ``--inspect-brk`` opens the V8 "
        "  inspector on port 9229 (or the configured port). "
        "  Anyone who can reach that port has full debugger "
        "  control: read process memory (incl. secrets), set "
        "  breakpoints, and execute arbitrary code in the "
        "  Node context.\n\n"
        "If your image needs an APM-style preload (Datadog, "
        "Sentry, OpenTelemetry), scope it to the specific "
        "service entrypoint via the agent's own startup wrapper "
        "rather than baking it into ``ENV NODE_OPTIONS``. The "
        "image-wide form applies to every Node process — "
        "including ``npm`` and ``yarn`` themselves — which "
        "broadens the attack surface unnecessarily."
    ),
    docs_note=(
        "Fires when ``ENV NODE_OPTIONS`` contains any of:\n\n"
        "* ``--require=<path>`` or ``--import=<path>`` "
        "  (preload a module on every Node startup)\n"
        "* ``--inspect`` / ``--inspect=...`` / "
        "  ``--inspect-brk`` (open V8 inspector port)\n\n"
        "Safe flags (``--max-old-space-size=``, "
        "``--enable-source-maps``, "
        "``--unhandled-rejections=throw``, etc.) pass. The rule "
        "flags the *primitive*, not the value — even an "
        "innocent-looking ``--require=./preload.js`` is the "
        "same shape as the malicious one, and the security "
        "decision is at the build-policy layer."
    ),
    known_fp=(
        "Sanitizer / APM / coverage tools sometimes legitimately "
        "use ``--require`` to inject their agent. Suppress with "
        "a rationale that names the specific agent and the path "
        "to its module. The rule deliberately flags the pattern "
        "because the same shape is the runtime-injection "
        "primitive Shai-Hulud-class npm worms exploit.",
    ),
)


# ``--require=<path>``, ``--require <path>``, and the newer ES-module
# variant ``--import=<path>``. Inspector flags accept an optional
# ``=host:port`` or ``=<port>``; the bare flag also fires.
_UNSAFE_FLAG_RE = re.compile(
    r"--(?:require|import)(?:=|\s+)\S+"
    r"|--inspect(?:-brk)?(?:=\S+)?\b",
    re.IGNORECASE,
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "NODE_OPTIONS":
            continue
        if not isinstance(value, str):
            continue
        match = _UNSAFE_FLAG_RE.search(value)
        if match is None:
            continue
        offenders.append(f"L{line_no}: ``{match.group(0)}`` in NODE_OPTIONS")
    passed = not offenders
    desc = (
        "No ``ENV NODE_OPTIONS`` declaration preloads code or "
        "opens an inspector."
        if passed else
        f"{len(offenders)} ``ENV NODE_OPTIONS`` declaration(s) "
        f"carry a runtime-injection / debugger flag: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The flag applies "
        f"to every Node process the image launches."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
