"""GOMOD-012. require / replace targets an insecure or non-canonical host."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GoModFile

RULE = Rule(
    id="GOMOD-012",
    title="go.mod require / replace targets an insecure or non-canonical host",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-319"),
    recommendation=(
        "Point every module coordinate at a canonical hostname. A "
        "module path whose host is a bare IP literal or carries an "
        "explicit ``:port`` is fetched over a non-canonical channel: "
        "a bare IP pins the fetch to one box with no DNS / TLS-name "
        "binding (trivial to spoof on a shared network), and a "
        "custom port usually means a self-hosted proxy / VCS that "
        "sits outside the public module-proxy + checksum-database "
        "guarantees. Replace the coordinate with the canonical "
        "``host/path`` form. If the dependency genuinely lives on "
        "an internal host, front it with a TLS-terminating canonical "
        "name (not a raw IP / port) and keep ``GOINSECURE`` scoped "
        "narrowly rather than disabling sum verification globally."
    ),
    docs_note=(
        "Walks every ``require`` path and every ``replace`` target "
        "(the right-hand module coordinate; local-path replaces are "
        "GOMOD-002's surface and are skipped) and fires when the "
        "host component is non-canonical: a bare IPv4 / "
        "bracketed-IPv6 literal as the host, or an explicit "
        "``host:port``. Canonical Go module paths resolve a real "
        "hostname (no scheme, no port), so either shape is a "
        "downgrade or a self-hosted-proxy smell.\n\n"
        "The module-graph analog of the PyPI / JFrog insecure-host "
        "rules (PYPI-003, PYPI-016). Operates on already-parsed "
        "coordinates, so it adds no network surface. Note that a "
        "scheme prefix (``http://`` / ``https://``) never appears "
        "in a well-formed go.mod coordinate, so the rule keys off "
        "the host shape rather than a URL scheme."
    ),
    known_fp=(
        "Self-hosted VCS or module proxies reached on a custom "
        "port over a trusted internal network may legitimately use "
        "a ``host:port`` coordinate. Suppress per directive with a "
        "rationale naming the network boundary; better, front the "
        "host with a TLS-terminating canonical name so the "
        "coordinate is a plain ``host/path``.",
    ),
    incident_refs=(
        "Insecure module fetch is the Go analog of the classic "
        "dependency MITM: a runner that resolves a module over "
        "plain HTTP or a spoofable bare IP can be served "
        "attacker-controlled bytes, and a coordinate that bypasses "
        "the canonical proxy also bypasses the sum-database "
        "transparency log.",
    ),
    exploit_example=(
        "// Vulnerable: bare-IP host + custom-port replace target.\n"
        "module example.com/myapp\n"
        "go 1.22\n"
        "require 10.0.0.42/team/util v1.0.0\n"
        "replace example.com/x => git.internal:8443/mirror/x v1.0.0\n"
        "\n"
        "// Attack: a peer on the runner's network answers for\n"
        "// 10.0.0.42 and serves a backdoored module. No TLS name\n"
        "// binding and no canonical proxy means the sum database\n"
        "// never sees the real bytes, so go mod verify can't catch\n"
        "// the swap.\n"
        "\n"
        "// Safe: canonical hostname coordinates.\n"
        "require git.internal.example.com/team/util v1.0.0"
    ),
)


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _host_issue(path: str) -> str | None:
    """Return a one-phrase reason when *path*'s host is non-canonical.

    A canonical Go module path is ``host/segments...`` with a real
    hostname (no scheme, no port). Returns ``None`` for canonical
    paths.
    """
    p = path.strip()
    if not p:
        return None
    host = p.split("/", 1)[0]
    # Bracketed IPv6 literal, optionally with a trailing port.
    if host.startswith("["):
        return "bracketed-IP host"
    if ":" in host:
        return "explicit host:port"
    if _IPV4_RE.match(host):
        return "bare IP host"
    return None


def check(pom: GoModFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[tuple[str, int]] = set()

    def _record(path: str, line_no: int, kind: str) -> None:
        issue = _host_issue(path)
        if issue is None:
            return
        key = (path, line_no)
        if key in seen:
            return
        seen.add(key)
        offenders.append(f"{path} ({kind}: {issue})")
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))

    for req in pom.requires:
        _record(req.path, req.line_no, "require")
    for rep in pom.replaces:
        if rep.is_local:
            continue
        _record(rep.new_path, rep.line_no, "replace target")

    passed = not offenders
    desc = (
        "Every require / replace coordinate uses a canonical host."
        if passed else
        f"{len(offenders)} coordinate(s) target an insecure / "
        f"non-canonical host: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The fetch bypasses "
        f"TLS name binding and / or the canonical module proxy, so "
        f"the bytes can be swapped without tripping go mod verify."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
