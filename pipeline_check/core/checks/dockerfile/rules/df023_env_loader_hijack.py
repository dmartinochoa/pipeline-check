"""DF-023, ``ENV`` sets a dynamic-loader hijack variable."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-023",
    title="ENV sets a dynamic-loader hijack variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-426",),
    recommendation=(
        "Don't bake ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` / "
        "``LD_AUDIT`` into the image. If a specific binary needs a "
        "non-standard library lookup, set the env var in the binary's "
        "own ``ENTRYPOINT`` wrapper so the override is scoped to that "
        "process, or, better, configure ``/etc/ld.so.conf.d/`` and "
        "rerun ``ldconfig`` at build time. A baked-in ``LD_*`` value "
        "applies to every process the image launches, including any "
        "shell an attacker reaches after an exploit."
    ),
    docs_note=(
        "``LD_PRELOAD``, ``LD_LIBRARY_PATH``, and ``LD_AUDIT`` are "
        "consulted by ``ld-linux`` for every dynamically-linked binary "
        "the image runs. A baked-in value gives an attacker who can "
        "drop a file inside the container (via a writable mount, a "
        "vulnerable upload handler, a build-stage hold-over) the "
        "ability to hook ``libc`` calls in privileged processes, "
        "intercept TLS, or shim ``execve`` to reroute commands. "
        "``LD_LIBRARY_PATH`` pointing at a writable directory is the "
        "milder shape of the same risk: a planted ``libc.so.6`` "
        "shadows the system lib for every later binary."
    ),
    known_fp=(
        "Sanitizer-instrumented images (``LD_PRELOAD=libasan.so``) "
        "and APM agent hooks (``LD_PRELOAD=/opt/dynatrace/...``) are "
        "legitimate. Suppress the finding for the specific Dockerfile "
        "with a one-line rationale; the rule deliberately catches the "
        "pattern because the same shape is the standard "
        "loader-hijack escalation primitive.",
    ),
    exploit_example=(
        "# Vulnerable: ``ENV LD_PRELOAD=/tmp/lib.so`` (or\n"
        "# ``LD_LIBRARY_PATH`` to a writable directory,\n"
        "# ``PYTHONPATH``, ``CLASSPATH``) configures the dynamic\n"
        "# loader to consult an attacker-influencable location\n"
        "# at runtime. A write into ``/tmp`` then runs arbitrary\n"
        "# code in every process the container starts.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "ENV LD_PRELOAD=/tmp/libhook.so\n"
        "CMD [\"/usr/local/bin/app\"]\n"
        "\n"
        "# Safe: no loader-hijack env vars in the image. If a\n"
        "# library actually needs to override loader paths, do\n"
        "# it inside the app's startup logic against a fixed,\n"
        "# read-only path, not via process env.\n"
        "FROM ubuntu@sha256:abc123...\n"
        "CMD [\"/usr/local/bin/app\"]"
    ),
)

#: ``ld.so`` honors each of these for dynamic linking. ``LD_AUDIT``
#: is the audit-API analog and is a hijack vector for the same reasons.
_HIJACK_VARS: frozenset[str] = frozenset({
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
})


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key not in _HIJACK_VARS:
            continue
        # Empty assignment (``ENV LD_PRELOAD=``) intentionally clears the
        # variable for child processes and is the recommended way to
        # turn off an inherited hijack from a base image, not a finding.
        if not value:
            continue
        offenders.append(f"L{line_no}: ENV {key}={value[:40]}"
                         f"{'…' if len(value) > 40 else ''}")
    passed = not offenders
    desc = (
        "No ``ENV`` directive sets a dynamic-loader hijack variable."
        if passed else
        f"{len(offenders)} ``ENV`` directive(s) set a loader-hijack "
        f"variable: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The value applies to "
        f"every process the image launches."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
