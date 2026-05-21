"""DF-004, ``RUN`` body contains curl-pipe / wget-pipe to interpreter."""
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
    exploit_example=(
        "# Vulnerable: curl-pipe to bash trusts both the network\n"
        "# (any MITM substitutes the script in flight) and the host\n"
        "# (a compromised installer endpoint silently serves attacker\n"
        "# code). The script then runs as root inside the build\n"
        "# context, so anything it writes lands in the final image.\n"
        "FROM ubuntu:24.04@sha256:abc123...\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates\n"
        "RUN curl -fsSL https://example-installer.example/install.sh | bash\n"
        "\n"
        "# Safe: download to a file, verify a sha256 digest from a\n"
        "# trusted source (the project's signing key, the vendor's\n"
        "# release manifest), then execute. If the upstream content\n"
        "# changes the digest stops matching and the build fails\n"
        "# before the malicious code runs.\n"
        "FROM ubuntu:24.04@sha256:abc123...\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates\n"
        "RUN curl -fsSL https://example-installer.example/install.sh -o /tmp/install.sh \\\n"
        "    && echo 'a1b2c3d4...  /tmp/install.sh' | sha256sum -c - \\\n"
        "    && bash /tmp/install.sh \\\n"
        "    && rm /tmp/install.sh"
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
            #, keeps reporters' "click to jump to line" experience
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
