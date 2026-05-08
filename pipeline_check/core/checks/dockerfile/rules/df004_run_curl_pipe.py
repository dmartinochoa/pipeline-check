"""DF-004 — ``RUN`` body contains curl-pipe / wget-pipe to interpreter."""
from __future__ import annotations

from ..._primitives import remote_script_exec
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-004",
    title="RUN executes a remote script via curl-pipe / wget-pipe",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download to a file, verify checksum or signature, then "
        "execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c "
        "<(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor "
        "installers from well-known hosts (rustup.rs, get.docker.com, "
        "...) are reported with vendor_trusted=true so reviewers can "
        "calibrate."
    ),
    docs_note=(
        "Reuses ``_primitives/remote_script_exec.scan`` so the "
        "vocabulary matches the equivalent CI-side rules (GHA-016, "
        "GL-016, BB-012, ADO-016, CC-016, JF-016)."
    ),
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        line_offenders = 0
        for hit in remote_script_exec.scan(body):
            tag = " (vendor-trusted)" if hit.vendor_trusted else ""
            offenders.append(f"L{line_no}: {hit.kind} -> {hit.host}{tag}")
            line_offenders += 1
        if line_offenders:
            # One Location per RUN line that contained at least one hit
            # — keeps reporters' "click to jump to line" experience
            # clean even when a single RUN piped two installers.
            locations.append(Location(
                path=df.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No ``RUN`` body invokes curl-pipe / wget-pipe to an interpreter."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies pipe a remote script "
        f"to a shell: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
