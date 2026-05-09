"""Implementation of the 100+ pipeline-check autofixers.

Imported as a side effect from ``pipeline_check.core.autofix.__init__``
so every ``@register(...)`` decorator runs at package import time.
External callers should import names from ``pipeline_check.core.autofix``
(the package), not from here.

This module's split is mechanical at the moment . one container for
every fixer the scanner ships. Future hygiene work can break it apart
by category (one module per provider, plus shared regex helpers); the
package facade in ``__init__.py`` already supports that pattern.
"""
from __future__ import annotations

import re

from ..checks.base import Finding
from . import _FIXERS, register

# Used by helpers below that bind their callable into ``_FIXERS`` for
# multiple check IDs in a single ``for`` loop. ``Finding`` is referenced
# in fixer signatures.
_ = (_FIXERS, Finding)

# ── Fixers ────────────────────────────────────────────────────────────────


_TOPLEVEL_KEY_RE = re.compile(r"^(?:permissions|jobs|on|name|env|defaults)\s*:",
                              re.MULTILINE)

# actions/checkout step, capturing leading indent + the full action
# line so we can anchor subsequent edits relative to it.
#
# Handles two styles:
#   (1) `- uses: actions/checkout@v4`    — single-line step
#   (2) `- name: Checkout`               — step with separate name
#       `  uses: actions/checkout@v4`
#
# The indent group always captures the column the `uses:` key starts
# at, whether that's after a leading `- ` (form 1) or two spaces under
# a named step (form 2). Downstream edits use that column to compute
# the right sub-indent for the `with:` block.
_CHECKOUT_USES_RE = re.compile(
    # ``prefix`` captures everything before ``uses:`` so the step's
    # indent column can be derived regardless of form. Its length is
    # the column number ``uses:`` (and therefore ``with:``) lives at.
    r"^(?P<prefix> *(?:-\s+)?)uses:\s*actions/checkout@\S+\s*$",
    re.MULTILINE,
)


@register("GHA-004")
def _fix_gha004(content: str, finding: Finding) -> str | None:
    """Insert ``permissions: contents: read`` at the top of the workflow.

    Idempotent: returns ``None`` if a top-level ``permissions:`` key
    already exists.
    """
    for m in _TOPLEVEL_KEY_RE.finditer(content):
        if m.group(0).split(":", 1)[0] == "permissions":
            return None

    # Insert the block before the first `jobs:` (the canonical anchor)
    # or, if no jobs: exists, before the first `on:` trigger.
    anchor = re.search(r"^jobs\s*:", content, re.MULTILINE) or \
             re.search(r"^on\s*:", content, re.MULTILINE)
    if anchor is None:
        return None
    insert_at = anchor.start()
    block = "permissions:\n  contents: read\n\n"
    return content[:insert_at] + block + content[insert_at:]


@register("GHA-002")
def _fix_gha002(content: str, finding: Finding) -> str | None:
    """Add ``persist-credentials: false`` under every actions/checkout step.

    Doesn't resolve the underlying GHA-002 (pull_request_target +
    PR head) on its own — that requires a workflow redesign — but
    the checkout option is a defense-in-depth measure that reduces
    the blast radius of the issue and is always safe to apply.
    Idempotent: skips checkout steps that already set the flag.
    """
    edits: list[tuple[int, int, str]] = []
    for m in _CHECKOUT_USES_RE.finditer(content):
        # ``uses:`` lives at column len(prefix). ``with:`` is a sibling
        # (same column) and its children live at +2 more spaces.
        uses_col = " " * len(m.group("prefix"))
        child_col = uses_col + "  "
        after = content[m.end():]
        # A ``with:`` block sits right under the uses line at the same
        # column, followed by at least one child indented two spaces
        # deeper. Recognize either style of quoting for the child.
        block_match = re.match(
            r"\n" + re.escape(uses_col) + r"with:\s*\n"
            r"(?:" + re.escape(child_col) + r"\S[^\n]*\n?)+",
            after,
        )
        if block_match:
            existing_block = block_match.group(0)
            if "persist-credentials" in existing_block:
                continue
            # Append the flag to the existing with block. Ensure the
            # inserted line ends in a newline even when the matched
            # block was at EOF without one.
            insertion = f"{child_col}persist-credentials: false\n"
            insert_at = m.end() + block_match.end()
            if not content[m.end():].endswith("\n") and insert_at == len(content):
                insertion = "\n" + insertion
            edits.append((insert_at, insert_at, insertion))
        else:
            # No with: block — add one right after the uses line.
            insertion = (
                f"\n{uses_col}with:\n"
                f"{child_col}persist-credentials: false"
            )
            edits.append((m.end(), m.end(), insertion))
    if not edits:
        return None
    # Apply edits from the end backward so earlier offsets stay valid.
    out = content
    for start, end, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[end:]
    return out


@register("GHA-008")
@register("GL-008")
@register("BB-008")
@register("ADO-008")
@register("CC-008")
def _fix_gha008(content: str, finding: Finding) -> str | None:
    """Replace credential-shaped literals with ``<REDACTED>`` + TODO comment.

    A defensive edit: the scanner already flagged these as compromised
    (they're in plaintext YAML, which is forkable and logged), so
    scrubbing the value from the repo is always safe. The operator
    still needs to rotate the key and wire up a real secret — we
    leave a ``# TODO:`` comment so the change is visible in review.

    Registered for all YAML-based providers (GHA, GL, BB, ADO). The
    fixer operates on raw text, so the same logic works across all
    YAML dialects. Jenkins (JF-008) is excluded — Groovy syntax
    needs a different approach.
    """
    from ..checks._patterns import SECRET_VALUE_RE
    out_lines: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        new_line = line
        # Conservative: only redact whole-token matches on the RHS of
        # a ``key: value`` pair, not inside arbitrary scripts.
        m = re.match(r"^(\s*[^#:\n]+:\s*)(\S+)(\s*)(#.*)?(\n?)$", new_line)
        if m:
            prefix, value, trailing_ws, comment, newline = m.groups()
            stripped = value.strip("\"'")
            if SECRET_VALUE_RE.fullmatch(stripped) or stripped.startswith("AKIA"):
                # Preserve the operator's existing comment (if any)
                # alongside our TODO marker — throwing it away loses
                # ticket numbers, blame context, or other hints that
                # the original author left in the file.
                todo = "# TODO(pipeline-check): rotate and wire up a secret"
                if comment:
                    original = comment.lstrip("#").strip()
                    todo = f"# {original} -- TODO(pipeline-check): rotate and wire up a secret"
                new_line = (
                    f"{prefix}\"<REDACTED>\"{trailing_ws or ''}"
                    f"  {todo}\n"
                )
                changed = True
        out_lines.append(new_line)
    if not changed:
        return None
    return "".join(out_lines)


# ── Timeout fixer ──────────────────────────────────────────────────────


@register("GHA-015")
def _fix_gha015(content: str, finding: Finding) -> str | None:
    """Insert ``timeout-minutes: 30`` into jobs that lack one.

    Scans for job-level keys under ``jobs:`` and inserts the timeout
    as the first property of each job that doesn't already have one.
    Idempotent: skips jobs that already declare ``timeout-minutes``.
    """
    lines = content.splitlines(keepends=True)
    in_jobs = False
    job_indent: str | None = None  # indent string of job-level keys
    result: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # Detect `jobs:` top-level key.
        if re.match(r"^jobs\s*:", stripped):
            in_jobs = True
            job_indent = None  # reset — will be learned from first child
            result.append(line)
            i += 1
            continue
        # Detect another top-level key (exits jobs block).
        if in_jobs and re.match(r"^\S", stripped) and not stripped.startswith("#"):
            in_jobs = False
        if in_jobs and stripped and not stripped.startswith("#"):
            # Learn the job indent from the first non-blank, non-comment
            # line under `jobs:`.
            leading = len(line) - len(line.lstrip())
            if job_indent is None and leading > 0:
                job_indent = " " * leading
            # Only match keys at exactly the job indent level.
            if (
                job_indent is not None
                and line.startswith(job_indent)
                and leading == len(job_indent)
                and re.match(r"\w[\w-]*:\s*$", line.lstrip())
            ):
                child_indent = job_indent + "  "
                result.append(line)
                i += 1
                # Scan ahead to check if timeout-minutes already exists.
                has_timeout = False
                j = i
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.rstrip()
                    if next_stripped and not next_stripped.startswith("#"):
                        next_indent = len(next_line) - len(next_line.lstrip())
                        if next_indent <= len(job_indent):
                            break
                    if "timeout-minutes" in next_line:
                        has_timeout = True
                        break
                    j += 1
                if not has_timeout:
                    result.append(f"{child_indent}timeout-minutes: 30\n")
                    changed = True
                continue
        result.append(line)
        i += 1
    if not changed:
        return None
    return "".join(result)


# ── GitLab / Azure timeout fixers ──────────────────────────────────────
#
# GitLab and Azure use the same top-level-job pattern as GitHub but with
# different timeout key names.  Rather than duplicate the scan logic we
# share a generic helper that takes the keyword and the value string.


def _fix_yaml_timeout(
    content: str, keyword: str, value: str, top_key: str | None = None,
) -> str | None:
    """Insert *keyword*: *value* into every top-level job missing it.

    *top_key* is an optional ``jobs:`` equivalent (Azure uses it);
    GitLab jobs live at the root alongside non-job keys, so *top_key*
    is ``None`` for that provider — we treat every root-level mapping
    key that isn't a known GitLab meta key as a job.
    """
    _GL_META = {
        "default", "include", "stages", "variables", "workflow",
        "image", "services", "cache", "before_script", "after_script",
        "pages",
    }
    lines = content.splitlines(keepends=True)
    result: list[str] = []
    changed = False
    i = 0

    if top_key is not None:
        # ── Azure-style: jobs live under a top-level key ──────────
        in_block = False
        job_indent: str | None = None
        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()
            if re.match(re.escape(top_key) + r"\s*:", stripped) and not line[0].isspace():
                in_block = True
                job_indent = None
                result.append(line)
                i += 1
                continue
            if in_block and stripped and not stripped.startswith("#") and not line[0].isspace():
                in_block = False
            if in_block and stripped and not stripped.startswith("#"):
                leading = len(line) - len(line.lstrip())
                if job_indent is None and leading > 0:
                    job_indent = " " * leading
                if (
                    job_indent is not None
                    and leading == len(job_indent)
                    and re.match(r"\w[\w-]*:\s*$", line.lstrip())
                ):
                    child_indent = job_indent + "  "
                    result.append(line)
                    i += 1
                    has_kw = _scan_for_key(lines, i, keyword, len(job_indent))
                    if not has_kw:
                        result.append(f"{child_indent}{keyword}: {value}\n")
                        changed = True
                    continue
            result.append(line)
            i += 1
    else:
        # ── GitLab-style: jobs are root-level keys ────────────────
        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()
            if (
                stripped
                and not stripped.startswith("#")
                and not line[0].isspace()
                and re.match(r"[\w][\w-]*:\s*$", stripped)
                and stripped.split(":")[0] not in _GL_META
            ):
                child_indent = "  "
                result.append(line)
                i += 1
                has_kw = _scan_for_key(lines, i, keyword, 0)
                if not has_kw:
                    result.append(f"{child_indent}{keyword}: {value}\n")
                    changed = True
                continue
            result.append(line)
            i += 1

    if not changed:
        return None
    return "".join(result)


def _scan_for_key(
    lines: list[str], start: int, keyword: str, parent_indent: int,
) -> bool:
    """Return True if *keyword* appears inside the block starting at *start*."""
    j = start
    while j < len(lines):
        ln = lines[j]
        s = ln.rstrip()
        if s and not s.startswith("#"):
            ind = len(ln) - len(ln.lstrip())
            if ind <= parent_indent:
                break
        if keyword in ln:
            return True
        j += 1
    return False


@register("GL-015")
def _fix_gl015(content: str, finding: Finding) -> str | None:
    return _fix_yaml_timeout(content, "timeout", "30 minutes")


@register("ADO-015")
def _fix_ado015(content: str, finding: Finding) -> str | None:
    """Insert ``timeoutInMinutes: 30`` into Azure ``- job:`` list items.

    Azure jobs are YAML list items (``- job: Name``), not mapping keys.
    """
    _JOB_ITEM_RE = re.compile(r"^(\s*)- job:\s*\S+")
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _JOB_ITEM_RE.match(line)
        if m:
            base_indent = m.group(1)
            # Properties of this job item are at base_indent + 2 spaces
            child_indent = base_indent + "  "
            out.append(line)
            i += 1
            has_kw = _scan_for_key(lines, i, "timeoutInMinutes", len(base_indent))
            if not has_kw:
                out.append(f"{child_indent}timeoutInMinutes: 30\n")
                changed = True
            continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── Curl-pipe comment-out ──────────────────────────────────────────────

_CURL_PIPE_LINE_RE = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b"
    r"|(?:curl|wget)\s+[^\n|]*\|\s*(?:python|perl|ruby)\b",
)

_TODO_CURL = "TODO(pipeline-check): download, verify checksum, then execute"


def _comment_curl_pipe(content: str, finding: Finding) -> str | None:
    """Comment out curl-pipe / wget-pipe lines across all providers."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        # Skip lines that are already comments or already have our marker.
        if _TODO_CURL in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if _CURL_PIPE_LINE_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            comment_char = "#"
            out.append(f"{indent}{comment_char} {_TODO_CURL}\n")
            out.append(f"{indent}{comment_char} {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-016", "GL-016", "ADO-016", "BB-012", "JF-016", "CC-016"):
    register(_cid)(_comment_curl_pipe)


# ── Docker --privileged removal ────────────────────────────────────────

_DOCKER_FLAG_RE = re.compile(
    r"\s+--privileged(?=\s|$)"
    r"|\s+--cap-add\s+\S+"
    r"|\s+--net[= ]host"
    r"|\s+-v\s+/[^:\s]*:/\S*",
)


def _strip_docker_flags(content: str, finding: Finding) -> str | None:
    """Strip --privileged, --cap-add, --net=host, -v /host:/ from docker run."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if "docker" in line and _DOCKER_FLAG_RE.search(line):
            new_line = _DOCKER_FLAG_RE.sub("", line)
            # Collapse multiple spaces left by removals.
            new_line = re.sub(r"  +", " ", new_line)
            if new_line != line:
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-017", "GL-017", "ADO-017", "BB-013", "JF-017", "CC-017"):
    register(_cid)(_strip_docker_flags)


# ── Insecure package-install flag removal ──────────────────────────────

_PKG_UNSAFE_FLAG_RE = re.compile(
    r"\s+--index-url\s+http://\S+"
    r"|\s+--extra-index-url\s+http://\S+"
    r"|\s+--trusted-host\s+\S+"
    r"|\s+--registry[= ]http://\S+"
    r"|\s+--no-verify"
)


def _strip_pkg_flags(content: str, finding: Finding) -> str | None:
    """Remove insecure registry / trust-override flags from package install."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _PKG_UNSAFE_FLAG_RE.search(line):
            new_line = _PKG_UNSAFE_FLAG_RE.sub("", line)
            new_line = re.sub(r"  +", " ", new_line)
            if new_line != line:
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-018", "GL-018", "ADO-018", "BB-014", "JF-018", "CC-018"):
    register(_cid)(_strip_pkg_flags)


# ── Jenkins secret redaction (Groovy syntax) ───────────────────────────


@register("JF-008")
def _fix_jf008(content: str, finding: Finding) -> str | None:
    """Redact credential-shaped literals in Groovy source.

    Handles ``VAR = "AKIA..."`` and ``def x = "ghp_..."`` patterns.
    """
    from ..checks._patterns import SECRET_VALUE_RE

    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if "<REDACTED>" in line:
            out.append(line)
            continue
        # Groovy assignments: VAR = "value" or def var = "value"
        m = re.match(
            r'^(\s*(?:def\s+)?[\w.]+\s*=\s*)["\']([^"\']+)["\'](.*)$',
            line,
        )
        if m:
            prefix, value, rest = m.groups()
            if SECRET_VALUE_RE.fullmatch(value) or value.startswith("AKIA"):
                todo = "// TODO(pipeline-check): rotate and wire up a credential"
                new_line = f'{prefix}"<REDACTED>"  {todo}\n'
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


# ── BB-005 Bitbucket timeout fixer ───────────────────────────────────


@register("BB-005")
def _fix_bb005(content: str, finding: Finding) -> str | None:
    """Insert ``max-time: 120`` into Bitbucket steps missing it.

    Bitbucket steps are list items under ``- step:``. Scans for
    ``- step:`` markers and checks whether the step's child block
    already declares ``max-time:``.
    """
    _STEP_RE = re.compile(r"^(\s*)- step:\s*$")
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _STEP_RE.match(line)
        if m:
            base_indent = m.group(1)
            child_indent = base_indent + "    "  # step children are 4 spaces in
            out.append(line)
            i += 1
            has_timeout = _scan_for_key(lines, i, "max-time", len(base_indent))
            if not has_timeout:
                out.append(f"{child_indent}max-time: 120\n")
                changed = True
            continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── JF-015 Jenkins timeout fixer ─────────────────────────────────────


@register("JF-015")
def _fix_jf015(content: str, finding: Finding) -> str | None:
    """Insert a TODO comment for adding a timeout wrapper.

    Jenkins timeout is Groovy syntax ``timeout(time: N, unit: 'MINUTES')``
    which can't be safely inserted by a text fixer, so we add a comment.
    """
    marker = "// TODO(pipeline-check): wrap with timeout(time: 30, unit: 'MINUTES')"
    if marker in content:
        return None
    # Find `pipeline {` and insert after it.
    m = re.search(r"^(\s*)pipeline\s*\{", content, re.MULTILINE)
    if m is None:
        return None
    insert_at = m.end()
    indent = m.group(1) + "    "
    return content[:insert_at] + f"\n{indent}{marker}" + content[insert_at:]


# ── JF-011 Jenkins buildDiscarder fixer ─────────────────────────────


@register("JF-011")
def _fix_jf011(content: str, finding: Finding) -> str | None:
    """Insert a ``buildDiscarder`` option into a declarative pipeline.

    Targets ``options { … }`` when it exists, or inserts a new
    ``options`` block after ``agent`` otherwise. Scripted pipelines
    are skipped (they'd need ``properties([…])`` which is harder to
    splice safely).
    """
    discarder = "buildDiscarder(logRotator(numToKeepStr: '30'))"
    if "buildDiscarder" in content or "logRotator" in content:
        return None

    # Try inserting inside an existing `options { … }` block.
    m = re.search(r"^(\s*)options\s*\{", content, re.MULTILINE)
    if m:
        insert_at = m.end()
        indent = m.group(1) + "    "
        return content[:insert_at] + f"\n{indent}{discarder}" + content[insert_at:]

    # No options block — insert one after `agent …` (declarative only).
    m_pipeline = re.search(r"^(\s*)pipeline\s*\{", content, re.MULTILINE)
    if m_pipeline is None:
        return None
    base_indent = m_pipeline.group(1) + "    "
    # Find the closing line of the agent block (agent any / agent { … }).
    m_agent_simple = re.search(r"^(\s*)agent\s+\w+\s*$", content, re.MULTILINE)
    m_agent_block = re.search(r"^(\s*)agent\s*\{", content, re.MULTILINE)
    if m_agent_block:
        # Walk braces to find the end of the agent block.
        i = m_agent_block.end()
        depth = 1
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        insert_at = i
    elif m_agent_simple:
        insert_at = m_agent_simple.end()
    else:
        return None
    snippet = f"\n{base_indent}options {{\n{base_indent}    {discarder}\n{base_indent}}}"
    return content[:insert_at] + snippet + content[insert_at:]


# ── Pinning TODO comments ────────────────────────────────────────────

_TODO_PIN = "TODO(pipeline-check): pin to commit SHA"
_TODO_PIN_IMG = "TODO(pipeline-check): pin to digest"


@register("GHA-001")
def _fix_gha001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned action uses: references."""
    _USES_RE = re.compile(r"^(\s*-?\s*uses:\s*)(\S+@)([^#\s]+)(.*)$")
    _SHA_RE = re.compile(r"^[0-9a-f]{40}$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _USES_RE.match(line.rstrip("\n"))
        if m:
            prefix, action, ref, rest = m.groups()
            if not _SHA_RE.match(ref):
                new_line = f"{prefix}{action}{ref}{rest}  # {_TODO_PIN}\n"
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("GL-001")
def _fix_gl001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned image: references."""
    _IMAGE_RE = re.compile(r"^(\s*image:\s*)(\S+)(.*)$")
    _DIGEST_RE = re.compile(r"@sha256:")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN_IMG in line:
            out.append(line)
            continue
        m = _IMAGE_RE.match(line.rstrip("\n"))
        if m:
            prefix, image, rest = m.groups()
            if not _DIGEST_RE.search(image):
                new_line = f"{prefix}{image}{rest}  # {_TODO_PIN_IMG}\n"
                out.append(new_line)
                changed = True
                continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("BB-001")
def _fix_bb001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned pipe: references."""
    _PIPE_RE = re.compile(r"^(\s*(?:- )?pipe:\s*)(\S+)(.*)$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _PIPE_RE.match(line.rstrip("\n"))
        if m:
            new_line = f"{line.rstrip()}  # {_TODO_PIN}\n"
            out.append(new_line)
            changed = True
            continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


@register("ADO-001")
def _fix_ado001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned task: references."""
    _TASK_RE = re.compile(r"^(\s*-?\s*task:\s*)(\S+@\S+)(.*)$")
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        if _TODO_PIN in line:
            out.append(line)
            continue
        m = _TASK_RE.match(line.rstrip("\n"))
        if m:
            new_line = f"{line.rstrip()}  # {_TODO_PIN}\n"
            out.append(new_line)
            changed = True
            continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


# ── GHA-003 Script injection — env-var indirection ──────────────────


@register("GHA-003")
def _fix_gha003(content: str, finding: Finding) -> str | None:
    """Add env-var indirection for untrusted context expressions in run: blocks.

    Transforms:
        - run: echo "${{ github.event.pull_request.title }}"
    Into:
        - run: echo "$UNTRUSTED_INPUT"
          env:
            UNTRUSTED_INPUT: ${{ github.event.pull_request.title }}

    This moves the expression from shell interpolation (injectable) to
    environment variable binding (safe — GitHub sets the env var as a
    single string, not subject to shell parsing).
    """
    from ..checks.github.rules._helpers import UNTRUSTED_CONTEXT_RE

    _RUN_RE = re.compile(r"^(\s*-?\s*run:\s*[|>]?\s*)$|^(\s*-?\s*run:\s+)(\S.*)$")
    _TODO_INJECT = "TODO(pipeline-check): moved untrusted expression to env var"

    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if _TODO_INJECT in line:
            out.append(line)
            i += 1
            continue

        # Match `- run: <command>` (inline form)
        m = _RUN_RE.match(line.rstrip("\n"))
        if m and m.group(3):
            run_body = m.group(3)
            contexts = list(UNTRUSTED_CONTEXT_RE.finditer(run_body))
            if contexts:
                prefix = m.group(2)
                indent = " " * len(prefix)
                new_body = run_body
                env_vars: list[tuple[str, str]] = []
                for idx, ctx_m in enumerate(reversed(contexts)):
                    expr = ctx_m.group(0)
                    # Derive an env var name from the expression
                    var_name = _expr_to_env_name(expr)
                    if idx > 0:
                        var_name = f"{var_name}_{idx}"
                    new_body = new_body[:ctx_m.start()] + f"${var_name}" + new_body[ctx_m.end():]
                    env_vars.append((var_name, expr))
                env_vars.reverse()
                out.append(f"{prefix}{new_body}  # {_TODO_INJECT}\n")
                out.append(f"{indent}env:\n")
                for var_name, expr in env_vars:
                    out.append(f"{indent}  {var_name}: {expr}\n")
                changed = True
                i += 1
                continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


def _expr_to_env_name(expr: str) -> str:
    """Convert ``${{ github.event.pull_request.title }}`` to ``PR_TITLE``."""
    inner = expr.strip("${} ")
    # Extract the last meaningful segment
    parts = inner.replace(".", "_").replace("[", "_").replace("]", "").split("_")
    # Take the last 2 meaningful parts
    meaningful = [p.upper() for p in parts if p and p not in ("GITHUB", "EVENT", "INPUTS")]
    if len(meaningful) >= 2:
        return "_".join(meaningful[-2:])
    return meaningful[-1] if meaningful else "UNTRUSTED_INPUT"


# ── CC-001 CircleCI orb pinning TODO ────────────────────────────────

_TODO_ORB = "TODO(pipeline-check): pin to exact semver (e.g. @5.1.0)"


@register("CC-001")
def _fix_cc001(content: str, finding: Finding) -> str | None:
    """Add TODO comment next to unpinned orb references."""
    _ORB_RE = re.compile(r"^(\s*\w[\w-]*:\s*)(\S+@\S+)(.*)$")
    _PINNED_RE = re.compile(r"@v?\d+\.\d+\.\d+")
    out: list[str] = []
    changed = False
    in_orbs = False
    for line in content.splitlines(keepends=True):
        stripped = line.rstrip()
        if re.match(r"^orbs\s*:", stripped):
            in_orbs = True
            out.append(line)
            continue
        if in_orbs and stripped and not stripped.startswith("#") and not line[0].isspace():
            in_orbs = False
        if in_orbs and _TODO_ORB not in line:
            m = _ORB_RE.match(line.rstrip("\n"))
            if m:
                prefix, ref, rest = m.groups()
                if not _PINNED_RE.search(ref):
                    new_line = f"{prefix}{ref}{rest}  # {_TODO_ORB}\n"
                    out.append(new_line)
                    changed = True
                    continue
        out.append(line)
    if not changed:
        return None
    return "".join(out)


# ── CC-015 CircleCI timeout fixer ───────────────────────────────────


@register("CC-015")
def _fix_cc015(content: str, finding: Finding) -> str | None:
    """Insert ``no_output_timeout: 30m`` into CircleCI run steps that lack it."""
    _RUN_KEY_RE = re.compile(r"^(\s*)- run:\s*$")
    lines = content.splitlines(keepends=True)
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _RUN_KEY_RE.match(line)
        if m:
            base_indent = m.group(1)
            child_indent = base_indent + "    "
            out.append(line)
            i += 1
            has_timeout = _scan_for_key(lines, i, "no_output_timeout", len(base_indent))
            if not has_timeout:
                out.append(f"{child_indent}no_output_timeout: 30m\n")
                changed = True
            continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── Token persistence comment-out ────────────────────────────────────

_TODO_TOKEN = "WARNING(pipeline-check): token written to persistent storage — remove this line"


def _comment_token_persist(content: str, finding: Finding) -> str | None:
    """Comment out lines that persist tokens to files/env."""
    from ..checks.bitbucket.rules.bb017_token_persistence import _TOKEN_PERSIST_RE as BB_RE
    from ..checks.github.rules.gha019_token_persistence import _TOKEN_PERSIST_RE as GHA_RE
    from ..checks.gitlab.rules.gl020_token_persistence import _TOKEN_PERSIST_RE as GL_RE

    persist_re = {"GHA-019": GHA_RE, "GL-020": GL_RE, "BB-017": BB_RE}
    pattern = persist_re.get(finding.check_id.upper())
    if pattern is None:
        return None

    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_TOKEN in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if pattern.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_TOKEN}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-019", "GL-020", "BB-017"):
    register(_cid)(_comment_token_persist)


# ── *-005 AWS long-lived key comment-out ──────────────────────────────

_TODO_AWS = "TODO(pipeline-check): switch to OIDC / IAM role — remove static AWS keys"
_AWS_KEY_LINE_RE = re.compile(
    r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|aws_access_key_id|aws_secret_access_key)"
)


def _comment_aws_keys(content: str, finding: Finding) -> str | None:
    """Comment out lines that declare static AWS access keys."""
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_AWS in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if _AWS_KEY_LINE_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            comment_char = "//" if finding.check_id.startswith("JF-") else "#"
            out.append(f"{indent}{comment_char} {_TODO_AWS}\n")
            out.append(f"{indent}{comment_char} {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-005", "GL-013", "BB-011", "ADO-014", "CC-005", "JF-004", "JF-010"):
    register(_cid)(_comment_aws_keys)


# ── Deploy environment stubs ─────────────────────────────────────────

_TODO_ENV = "TODO(pipeline-check): configure deployment environment"
_DEPLOY_NAME_RE = re.compile(r"(?i)(deploy|release|publish|promote)")


@register("GHA-014")
def _fix_gha014(content: str, finding: Finding) -> str | None:
    """Insert ``environment:`` placeholder into deploy-named GHA jobs."""
    lines = content.splitlines(keepends=True)
    in_jobs = False
    job_indent: str | None = None
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if re.match(r"^jobs\s*:", stripped):
            in_jobs = True
            job_indent = None
            out.append(line)
            i += 1
            continue
        if in_jobs and re.match(r"^\S", stripped) and not stripped.startswith("#"):
            in_jobs = False
        if in_jobs and stripped and not stripped.startswith("#"):
            leading = len(line) - len(line.lstrip())
            if job_indent is None and leading > 0:
                job_indent = " " * leading
            if (
                job_indent is not None
                and leading == len(job_indent)
                and re.match(r"\w[\w-]*:\s*$", line.lstrip())
            ):
                job_name = line.lstrip().split(":")[0]
                child_indent = job_indent + "  "
                out.append(line)
                i += 1
                if _DEPLOY_NAME_RE.search(job_name):
                    has_env = _scan_for_key(lines, i, "environment", len(job_indent))
                    if not has_env:
                        out.append(f"{child_indent}environment: # {_TODO_ENV}\n")
                        changed = True
                continue
        out.append(line)
        i += 1
    if not changed:
        return None
    return "".join(out)


# ── *-021 npm install → npm ci ───────────────────────────────────────

_NPM_INSTALL_RE = re.compile(r"\bnpm\s+install\b")


def _fix_npm_ci(content: str, finding: Finding) -> str | None:
    """Replace bare ``npm install`` with ``npm ci``."""
    if "npm ci" in content and "npm install" not in content:
        return None
    out = _NPM_INSTALL_RE.sub("npm ci", content)
    if out == content:
        return None
    return out


for _cid in ("GHA-021", "GL-021", "ADO-021", "BB-021", "JF-021", "CC-021"):
    register(_cid)(_fix_npm_ci)


# ── *-022 dependency-update command comment-out ──────────────────────

_TODO_DEP_UPDATE = "TODO(pipeline-check): remove dependency update command; use lockfile-pinned install"


def _comment_dep_update(content: str, finding: Finding) -> str | None:
    """Comment out dependency-update commands."""
    from ..checks.base import _DEP_UPDATE_TOOL_EXEMPT_RE, DEP_UPDATE_RE
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_DEP_UPDATE in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if DEP_UPDATE_RE.search(line) and not _DEP_UPDATE_TOOL_EXEMPT_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_DEP_UPDATE}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-022", "GL-022", "ADO-022", "BB-022", "JF-022", "CC-022"):
    register(_cid)(_comment_dep_update)


# ── *-023 TLS bypass comment-out ─────────────────────────────────────

_TODO_TLS = "TODO(pipeline-check): remove TLS/SSL verification bypass"


def _comment_tls_bypass(content: str, finding: Finding) -> str | None:
    """Comment out TLS verification bypass lines."""
    from ..checks.base import TLS_BYPASS_RE
    out: list[str] = []
    changed = False
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if _TODO_TLS in line or stripped.startswith("#") or stripped.startswith("//"):
            out.append(line)
            continue
        if TLS_BYPASS_RE.search(line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}# {_TODO_TLS}\n")
            out.append(f"{indent}# {stripped}")
            if not line.endswith("\n"):
                out[-1] += "\n"
            changed = True
        else:
            out.append(line)
    if not changed:
        return None
    return "".join(out)


for _cid in ("GHA-023", "GL-023", "ADO-023", "BB-023", "JF-023", "CC-023"):
    register(_cid)(_comment_tls_bypass)


# Cloud Build TLS bypass reuses the same heuristic as the CI providers.
register("GCB-011")(_comment_tls_bypass)


# ── Kubernetes drop-line fixers (K8S-002/003/004/005) ────────────────
#
# These four rules all flag a YAML key set to ``true`` that should
# either be ``false`` or omitted (default false). The safe edit is to
# drop the line entirely; the cluster falls back to the secure default.
# Idempotent because the line being absent is the post-fix state.

# Each rule maps to one specific key. Stricter than a generic
# alternation so K8S-002 doesn't try to fix a hostPID issue and vice
# versa.
_K8S_DROP_TRUE_KEYS: dict[str, str] = {
    "K8S-002": "hostNetwork",
    "K8S-003": "hostPID",
    "K8S-004": "hostIPC",
    "K8S-005": "privileged",
}


def _fix_k8s_drop_true_line(content: str, finding: Finding) -> str | None:
    key = _K8S_DROP_TRUE_KEYS.get(finding.check_id.upper())
    if key is None:
        return None
    # Match a whole line: optional indent, the exact key, ``: true``,
    # optional inline comment. Keep an optional trailing newline so the
    # match consumes the line break too and we don't leave a blank gap.
    pat = re.compile(
        rf"^[ \t]*{re.escape(key)}\s*:\s*true\s*(?:#[^\n]*)?\n?",
        re.MULTILINE,
    )
    new = pat.sub("", content)
    if new == content:
        return None
    return new


for _cid in _K8S_DROP_TRUE_KEYS:
    register(_cid)(_fix_k8s_drop_true_line)


# ── Kubernetes flip-value fixers (K8S-006/007/008) ───────────────────
#
# These rules flag a securityContext field set to the unsafe value.
# Flipping in-place preserves the surrounding indent and any comment
# the operator left on the line. The "key is missing entirely" case
# (no securityContext at all) is left to manual edit — inserting a
# block at the right indent level is too easy to get wrong with text
# patches, and the rule's recommendation already explains the shape.

# Each entry: (key, unsafe_literal, safe_literal).
_K8S_FLIP_VALUE: dict[str, tuple[str, str, str]] = {
    "K8S-006": ("allowPrivilegeEscalation", "true", "false"),
    "K8S-007": ("runAsNonRoot", "false", "true"),
    "K8S-008": ("readOnlyRootFilesystem", "false", "true"),
}


def _fix_k8s_flip_value(content: str, finding: Finding) -> str | None:
    entry = _K8S_FLIP_VALUE.get(finding.check_id.upper())
    if entry is None:
        return None
    key, bad, good = entry
    pat = re.compile(
        rf"(^[ \t]*{re.escape(key)}\s*:\s*){re.escape(bad)}(\s*(?:#[^\n]*)?)$",
        re.MULTILINE,
    )
    new, n = pat.subn(rf"\g<1>{good}\g<2>", content)
    if n == 0:
        return None
    return new


for _cid in _K8S_FLIP_VALUE:
    register(_cid)(_fix_k8s_flip_value)


# ── Kubernetes comment-only TODO fixers (K8S-013, K8S-020) ───────────
#
# Some K8s findings can't be auto-rewritten safely. ``hostPath``
# volumes need to become ``persistentVolumeClaim`` references with a
# matching PVC manifest, which the scanner can't synthesize. A
# ClusterRoleBinding to ``cluster-admin`` needs a least-privilege
# Role drafted by hand. For both, the fixer leaves a ``TODO`` comment
# above the offending line so the change is visible in review.

_TODO_K8S_HOSTPATH = (
    "TODO(pipeline-check K8S-013): replace hostPath with a "
    "persistentVolumeClaim referencing a PVC scoped to this namespace"
)

_HOSTPATH_RE = re.compile(r"^(\s*)hostPath\s*:\s*$", re.MULTILINE)


@register("K8S-013")
def _fix_k8s013_hostpath(content: str, finding: Finding) -> str | None:
    if _TODO_K8S_HOSTPATH in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HOSTPATH_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_K8S_HOSTPATH}\n"))
    if not edits:
        return None
    out = content
    for start, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[start:]
    return out


_TODO_K8S_CLUSTER_ADMIN = (
    "TODO(pipeline-check K8S-020): replace cluster-admin binding with "
    "a least-privilege Role + RoleBinding scoped to a namespace"
)

# Match the roleRef body that points at cluster-admin or system:masters.
# Anchored to ``name:`` because that's the line carrying the
# offending value; a comment one line above is the most readable spot.
_CLUSTER_ADMIN_NAME_RE = re.compile(
    r"^(\s*)name\s*:\s*[\"']?(?:cluster-admin|system:masters)[\"']?\s*$",
    re.MULTILINE,
)


@register("K8S-020")
def _fix_k8s020_cluster_admin(content: str, finding: Finding) -> str | None:
    if _TODO_K8S_CLUSTER_ADMIN in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _CLUSTER_ADMIN_NAME_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_K8S_CLUSTER_ADMIN}\n"))
    if not edits:
        return None
    out = content
    for start, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[start:]
    return out


# ── K8S-001 image-pinning TODO ───────────────────────────────────────
#
# Comment-only fixer: pinning to a real digest needs an out-of-band
# registry lookup (``crane digest <ref>``) the scanner can't make.
# The TODO sits above each unpinned ``image:`` line.

_TODO_K8S_IMAGE_PIN = (
    "TODO(pipeline-check K8S-001): pin to a sha256 digest "
    "(``image: repo@sha256:<digest>``) — resolve via "
    "``crane digest <ref>`` or ``docker buildx imagetools inspect``"
)

# Match ``image: <ref>`` lines whose value lacks ``@sha256:``. Allows
# quoted values and inline comments. The container-spec convention
# is that ``image:`` keys only appear inside container entries —
# Kubernetes API objects don't reuse the key for anything else — so
# a plain key match is safe enough without anchoring to ``- name:``.
_K8S_IMAGE_RE = re.compile(
    r"^(?P<indent>\s*)image\s*:\s*[\"']?(?P<ref>[^\s\"'#]+)[\"']?\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("K8S-001")
def _fix_k8s001_image_pin(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each container ``image:`` line that lacks
    a sha256 digest.

    Idempotent via the marker. Lines whose value already contains
    ``@sha256:`` are skipped — they're already pinned.
    """
    if _TODO_K8S_IMAGE_PIN in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _K8S_IMAGE_RE.finditer(content):
        ref = m.group("ref")
        if "@sha256:" in ref:
            continue
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_K8S_IMAGE_PIN}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── K8S-028 hostPort drop ────────────────────────────────────────────
#
# Matches ``hostPort: <positive int>`` and drops the whole line.
# Distinct from the K8S_DROP_TRUE_KEYS family because the value here
# is numeric, not the literal ``true``. ``hostPort: 0`` is the unset
# sentinel and isn't matched (the rule itself ignores zero).

_K8S_HOSTPORT_RE = re.compile(
    r"^[ \t]*hostPort\s*:\s*[1-9]\d*\s*(?:#[^\n]*)?\n?",
    re.MULTILINE,
)


@register("K8S-028")
def _fix_k8s028_host_port(content: str, finding: Finding) -> str | None:
    """Drop ``hostPort: <N>`` lines. The container's ``containerPort``
    is unaffected — only the node-IP binding is removed. Operators who
    genuinely need node-port semantics should re-add it as part of a
    DaemonSet plus an explicit ``hostNetwork: true`` review."""
    new = _K8S_HOSTPORT_RE.sub("", content)
    if new == content:
        return None
    return new


# ── K8S-029 default-SA binding TODO ──────────────────────────────────

_TODO_K8S_DEFAULT_SA = (
    "TODO(pipeline-check K8S-029): bind permissions to a dedicated "
    "ServiceAccount, not 'default'. Every untargeted pod inherits "
    "this SA's grants — create a named SA and reference it explicitly"
)

# Match the ``name: default`` line of a binding subject. Anchored on
# ``name:`` because ``kind: ServiceAccount`` with ``name: default`` is
# the canonical shape; comments above the name read naturally.
_K8S_DEFAULT_SA_NAME_RE = re.compile(
    r"^(\s*)name\s*:\s*[\"']?default[\"']?\s*$",
    re.MULTILINE,
)


@register("K8S-029")
def _fix_k8s029_default_sa(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``name: default`` line in a subjects
    block.

    Comment-only because the right shape is to (a) create a named SA,
    (b) bind that SA explicitly, and (c) leave the default SA
    unbound. The fixer can't synthesize the named SA's manifest.
    """
    if _TODO_K8S_DEFAULT_SA in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _K8S_DEFAULT_SA_NAME_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_K8S_DEFAULT_SA}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── K8S-030 control-plane scheduling TODO ────────────────────────────

_TODO_K8S_CTRL_PLANE = (
    "TODO(pipeline-check K8S-030): drop control-plane "
    "nodeSelector / tolerations from non-system workloads. App pods "
    "belong on dedicated worker nodes, not on the API/etcd host"
)

_K8S_CTRL_PLANE_LABEL_RE = re.compile(
    r"^(\s*)(?:node-role\.kubernetes\.io/(?:control-plane|master))\s*:",
    re.MULTILINE,
)
_K8S_CTRL_PLANE_TOLERATION_KEY_RE = re.compile(
    r"^(\s*-?\s*)key\s*:\s*[\"']?"
    r"node-role\.kubernetes\.io/(?:control-plane|master)[\"']?\s*$",
    re.MULTILINE,
)


@register("K8S-030")
def _fix_k8s030_control_plane(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each control-plane targeting line.

    Both ``nodeSelector`` keys and ``tolerations`` keys are flagged so
    a single workload that targets both gets one TODO per line. Drop
    is tempting but unsafe — the workload may have other valid
    scheduling constraints below the offending line, and a structured
    YAML rewrite is out of scope for a text patch.
    """
    if _TODO_K8S_CTRL_PLANE in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _K8S_CTRL_PLANE_LABEL_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_K8S_CTRL_PLANE}\n"))
    for m in _K8S_CTRL_PLANE_TOLERATION_KEY_RE.finditer(content):
        indent_raw = m.group(1)
        indent_ws = indent_raw[: len(indent_raw) - len(indent_raw.lstrip())]
        edits.append((m.start(), f"{indent_ws}# {_TODO_K8S_CTRL_PLANE}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── GHA-034 reusable-workflow secrets: inherit TODO ──────────────────

_TODO_GHA_INHERIT = (
    "TODO(pipeline-check GHA-034): replace 'secrets: inherit' with an "
    "explicit allowlist (secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }) "
    "so a compromised callee can't reach unrelated credentials"
)

_GHA_SECRETS_INHERIT_RE = re.compile(
    r"^(\s*)secrets\s*:\s*[\"']?inherit[\"']?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@register("GHA-034")
def _fix_gha034_secrets_inherit(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``secrets: inherit`` line.

    Comment-only because the right shape requires the operator to
    name the secrets the callee actually needs, which the fixer
    can't infer from the calling YAML alone.
    """
    if _TODO_GHA_INHERIT in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _GHA_SECRETS_INHERIT_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_GHA_INHERIT}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── Cloud Build fixers ───────────────────────────────────────────────


_GCB_TIMEOUT_RE = re.compile(r"^timeout\s*:", re.MULTILINE)
_GCB_FIRST_TOPLEVEL_RE = re.compile(
    r"^(?:steps|substitutions|options|images|artifacts|tags|"
    r"availableSecrets|serviceAccount|logsBucket)\s*:",
    re.MULTILINE,
)


@register("GCB-005")
def _fix_gcb005_timeout(content: str, finding: Finding) -> str | None:
    """Insert ``timeout: '600s'`` at the top of cloudbuild.yaml.

    Idempotent: returns ``None`` if a top-level ``timeout:`` already
    exists. 600s is the longest of the conservative bounds the rule
    accepts; the operator can tune it down once the build's actual
    duration is known.
    """
    if _GCB_TIMEOUT_RE.search(content):
        return None
    anchor = _GCB_FIRST_TOPLEVEL_RE.search(content)
    if anchor is None:
        return None
    insert_at = anchor.start()
    return content[:insert_at] + "timeout: '600s'\n" + content[insert_at:]


_GCB_LOGGING_NONE_RE = re.compile(
    r"^[ \t]*logging\s*:\s*[\"']?NONE[\"']?\s*(?:#[^\n]*)?\n?",
    re.MULTILINE,
)


@register("GCB-014")
def _fix_gcb014_logging(content: str, finding: Finding) -> str | None:
    """Drop ``logging: NONE`` so Cloud Build falls back to logging
    enabled. The operator can re-pick a logging mode (``CLOUD_LOGGING_ONLY``,
    ``GCS_ONLY``, etc.) explicitly if the default isn't right for them.
    """
    new = _GCB_LOGGING_NONE_RE.sub("", content)
    if new == content:
        return None
    return new


# ── GCB-022 substitutionOption ALLOW_LOOSE drop ──────────────────────

# Match an indented ``substitutionOption: ALLOW_LOOSE`` line under
# ``options:`` and drop it. Cloud Build then falls back to the
# ``MUST_MATCH`` default — the safer behavior. Inline comments are
# consumed too so we don't leave a dangling ``# ...`` line.
_GCB_SUBOPT_LOOSE_RE = re.compile(
    r"^[ \t]*substitutionOption\s*:\s*[\"']?ALLOW_LOOSE[\"']?\s*"
    r"(?:#[^\n]*)?\n?",
    re.IGNORECASE | re.MULTILINE,
)


@register("GCB-022")
def _fix_gcb022_subopt_loose(content: str, finding: Finding) -> str | None:
    """Drop ``substitutionOption: ALLOW_LOOSE``.

    Cloud Build's default is ``MUST_MATCH``, which is what the rule's
    recommendation calls for. Dropping the explicit opt-in restores
    that default. The ``options:`` block is left in place even when
    this was its only entry — surrounding edits often add other
    options (logging, machine type, …) and an empty ``options: {}``
    is harmless.
    """
    new = _GCB_SUBOPT_LOOSE_RE.sub("", content)
    if new == content:
        return None
    return new


# ── GCB-021 worker-pool TODO ─────────────────────────────────────────

_TODO_GCB_POOL = (
    "TODO(pipeline-check GCB-021): add a private worker pool — "
    "pool: { name: 'projects/<PROJECT>/locations/<REGION>/workerPools/<NAME>' } "
    "— so the build runs inside your VPC instead of Google's shared "
    "default pool"
)
_GCB_OPTIONS_RE = re.compile(r"^(\s*)options\s*:\s*$", re.MULTILINE)


@register("GCB-021")
def _fix_gcb021_worker_pool(content: str, finding: Finding) -> str | None:
    """Insert a TODO above the ``options:`` block when no worker pool
    is configured.

    Idempotent on the marker. If ``options:`` doesn't exist, no-op
    (the rule's recommendation already covers the from-scratch case;
    inserting a top-level block from text is too easy to misindent).
    """
    if _TODO_GCB_POOL in content:
        return None
    m = _GCB_OPTIONS_RE.search(content)
    if m is None:
        return None
    indent = m.group(1)
    return (
        content[:m.start()]
        + f"{indent}# {_TODO_GCB_POOL}\n"
        + content[m.start():]
    )


_TODO_GCB_PIN = (
    "TODO(pipeline-check GCB-001): pin step image to a digest "
    "(``gcr.io/.../foo@sha256:<digest>``) instead of a mutable tag"
)

# Step image lines look like ``- name: 'gcr.io/cloud-builders/gcloud'``
# or ``  name: gcr.io/foo/bar:tag``. Match a name: key whose value
# contains a slash (the registry path) and *no* ``@sha256:`` digest.
_GCB_STEP_NAME_RE = re.compile(
    r"^(?P<indent>\s*-?\s*)name\s*:\s*[\"']?"
    r"(?P<image>[^\s\"'@]+/[^\s\"'@]+(?::[^\s\"'@]+)?)"
    r"[\"']?\s*$",
    re.MULTILINE,
)


@register("GCB-001")
def _fix_gcb001_pin_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each step image line that isn't pinned to
    a digest. Comment-only — pinning to a real digest needs an out-
    of-band registry lookup (``gcloud container images describe``)
    that the scanner can't make.
    """
    if _TODO_GCB_PIN in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _GCB_STEP_NAME_RE.finditer(content):
        image = m.group("image")
        if "@sha256:" in image:
            continue
        # The leading dash, if any, already lives in ``indent``. Pull
        # the comment indent off of just the whitespace prefix so it
        # lines up with the ``- name:`` token.
        indent_raw = m.group("indent")
        # ``\s*`` always matches (the empty string at minimum), so the
        # ``Match | None`` is in practice a Match. Use the slice form
        # to extract the leading whitespace without needing the regex
        # match object — equivalent and unambiguously-typed as ``str``.
        indent_ws = indent_raw[: len(indent_raw) - len(indent_raw.lstrip())]
        # If the indent contains a list dash, the comment goes at the
        # same column as the dash, not the ``name:`` key.
        edits.append((m.start(), f"{indent_ws}# {_TODO_GCB_PIN}\n"))
    if not edits:
        return None
    out = content
    for start, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[start:]
    return out


# ── Dockerfile comment-only TODO fixers ───────────────────────────────
#
# Dockerfile fixers stay comment-only: a transformative patch would
# need to know the runtime user UID, the application port, the base
# image's healthcheck command — none of which the scanner has.
# Comment-only TODOs surface the gap in code review where the author
# can supply the right value.

_TODO_DF_PIN = (
    "TODO(pipeline-check DF-001): pin base image by digest "
    "(``FROM image@sha256:...``) — `docker pull image:tag && "
    "docker images --digests` to get the digest"
)

_TODO_DF_USER = (
    "TODO(pipeline-check DF-002): drop to a non-root user before the "
    "final CMD (``RUN useradd --uid 1001 --create-home appuser`` "
    "+ ``USER appuser``)"
)

_TODO_DF_HEALTHCHECK = (
    "TODO(pipeline-check DF-007): add a HEALTHCHECK so the orchestrator "
    "can detect a hung container (``HEALTHCHECK CMD curl -fsS "
    "http://localhost:<port>/healthz || exit 1``)"
)

_TODO_DF_EXPOSE_SSH = (
    "TODO(pipeline-check DF-013): drop EXPOSE 22 — containers should "
    "not run sshd. Use ``docker exec`` / ``kubectl exec`` for shell "
    "access instead"
)

_TODO_DF_PATH = (
    "TODO(pipeline-check DF-017): drop the world-writable prefix "
    "(/tmp, /var/tmp, /dev/shm, /run/lock) from PATH, or move it "
    "to the tail so system bins shadow it"
)

_TODO_DF_COPY_CRED = (
    "TODO(pipeline-check DF-019): replace this COPY/ADD with a "
    "build-time mount (``RUN --mount=type=secret,id=<name>``) — the "
    "file's contents are otherwise baked into the image layer and "
    "recoverable by anyone who can pull the image"
)

_TODO_DF_ARG_CRED = (
    "TODO(pipeline-check DF-020): drop this credential-named ARG and "
    "use ``RUN --mount=type=secret,id=<name>`` instead. ``--build-arg`` "
    "values land in ``docker history`` even when the ARG has no default"
)


_DF_FROM_RE = re.compile(
    r"^(\s*)FROM\s+(?P<image>\S+)",
    re.MULTILINE,
)

_DF_EXPOSE_22_RE = re.compile(
    r"^(\s*)EXPOSE\s+(?:[^\n]*\b)?22\b",
    re.MULTILINE,
)

_DF_USER_RE = re.compile(r"^\s*USER\s+\S", re.MULTILINE)
_DF_HEALTHCHECK_RE = re.compile(r"^\s*HEALTHCHECK\b", re.MULTILINE)
_DF_FINAL_CMD_RE = re.compile(
    r"^(\s*)(?:CMD|ENTRYPOINT)\b", re.MULTILINE,
)

_DF_PATH_PREPEND_RE = re.compile(
    r"^(\s*)ENV\s+PATH\s*=\s*(?P<value>[^\n]+)$",
    re.MULTILINE,
)
_DF_PATH_WRITABLE_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "/run/lock")

# Match COPY/ADD lines whose source token looks like a credential file.
# Uses a quick basename / path-tail / extension test so the fixer's
# match shape mirrors the rule's; if the rule's catalog grows, only
# the rule needs to update — the fixer keeps annotating whatever the
# rule already flagged.
_DF_COPY_CRED_RE = re.compile(
    r"^(\s*)(?:COPY|ADD)\b[^\n]*?"
    r"(?:"
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.npmrc\b|\.pypirc\b|\.netrc\b|\.env\b"
    r"|\.git-credentials\b|\bterraform\.tfvars\b|\bkubeconfig\b"
    r"|\.aws/credentials\b|\.docker/config\.json\b|\.kube/config\b"
    r"|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.(?:pem|key|p12|pfx|jks)\b"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# Match ARG lines whose name looks credential-shaped — same regex
# the secret_shapes primitive uses (case-insensitive substring of
# password/passwd/secret/token/apikey/api_key/private_key).
_DF_ARG_CRED_RE = re.compile(
    r"^(\s*)ARG\s+"
    r"[A-Za-z0-9_]*"
    r"(?:password|passwd|secret|token|apikey|api_key|private_key)"
    r"[A-Za-z0-9_]*"
    r"(?:\s*=[^\n]*)?$",
    re.IGNORECASE | re.MULTILINE,
)


def _insert_comment_above(content: str, edits: list[tuple[int, str]]) -> str:
    """Apply [(start, text), ...] inserts in reverse so offsets stay valid."""
    out = content
    for start, text in sorted(edits, reverse=True):
        out = out[:start] + text + out[start:]
    return out


@register("DF-001")
def _fix_df001_pin_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above any FROM line that lacks a sha256 digest.

    Multi-stage Dockerfiles can have several FROM lines; we annotate
    each unpinned one. Stages already pinned by digest are left alone.
    Idempotent via the marker check.
    """
    if _TODO_DF_PIN in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _DF_FROM_RE.finditer(content):
        image = m.group("image")
        if "@sha256:" in image:
            continue
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_DF_PIN}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


@register("DF-002")
def _fix_df002_user_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above the final CMD/ENTRYPOINT when no USER is set.

    Idempotent: returns ``None`` if a USER directive already exists or
    the marker is present. The TODO sits at the natural spot where a
    ``USER appuser`` line would land (just before the runtime entry
    point).
    """
    if _TODO_DF_USER in content:
        return None
    if _DF_USER_RE.search(content):
        return None
    matches = list(_DF_FINAL_CMD_RE.finditer(content))
    if not matches:
        return None
    last = matches[-1]
    indent = last.group(1)
    return (
        content[:last.start()]
        + f"{indent}# {_TODO_DF_USER}\n"
        + content[last.start():]
    )


@register("DF-007")
def _fix_df007_healthcheck_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above the final CMD/ENTRYPOINT when no HEALTHCHECK."""
    if _TODO_DF_HEALTHCHECK in content:
        return None
    if _DF_HEALTHCHECK_RE.search(content):
        return None
    matches = list(_DF_FINAL_CMD_RE.finditer(content))
    if not matches:
        return None
    last = matches[-1]
    indent = last.group(1)
    return (
        content[:last.start()]
        + f"{indent}# {_TODO_DF_HEALTHCHECK}\n"
        + content[last.start():]
    )


@register("DF-013")
def _fix_df013_expose_ssh_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above any EXPOSE line publishing port 22."""
    if _TODO_DF_EXPOSE_SSH in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _DF_EXPOSE_22_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_DF_EXPOSE_SSH}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


@register("DF-017")
def _fix_df017_path_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above any ``ENV PATH=`` whose value prepends a
    world-writable prefix ahead of ``$PATH``.

    Comment-only because we can't safely rewrite the value: the
    operator may genuinely intend the writable dir to be in PATH at
    the tail. The TODO points at the correct shape.
    """
    if _TODO_DF_PATH in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _DF_PATH_PREPEND_RE.finditer(content):
        value = m.group("value")
        # Walk segments; flag if a writable prefix appears before
        # ``$PATH`` / ``${PATH}``.
        segs = [s.strip() for s in value.split(":")]
        offending = False
        for seg in segs:
            if seg in ("$PATH", "${PATH}"):
                break
            if any(
                seg == p or seg.startswith(p + "/")
                for p in _DF_PATH_WRITABLE_PREFIXES
            ):
                offending = True
                break
        if not offending:
            continue
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_DF_PATH}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


@register("DF-019")
def _fix_df019_copy_cred_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above any ``COPY``/``ADD`` whose source basename
    matches a credential filename.

    Comment-only because the fix is to *remove* the directive entirely
    and switch to ``RUN --mount=type=secret``; the operator has to
    supply the secret-id and the consumption pattern. The TODO points
    at the right shape.
    """
    if _TODO_DF_COPY_CRED in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _DF_COPY_CRED_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_DF_COPY_CRED}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


@register("DF-020")
def _fix_df020_arg_cred_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above any ``ARG`` whose name looks credential-shaped.

    Comment-only for the same reason as DF-019: the right shape uses
    ``RUN --mount=type=secret``, which requires the operator to wire
    up the secret source on their build invocation.
    """
    if _TODO_DF_ARG_CRED in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _DF_ARG_CRED_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_DF_ARG_CRED}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── Cloud Build comment-only TODO fixer (GCB-007) ────────────────────


_TODO_GCB_LATEST = (
    "TODO(pipeline-check GCB-007): pin secret to a specific Secret "
    "Manager version (``versions/<N>``) — ``versions/latest`` "
    "rotates silently and bypasses change review"
)
_GCB_VERSION_LATEST_RE = re.compile(
    r"^(\s*-?\s*)versionName\s*:\s*[\"']?[^\"'\n]*versions/latest[\"']?\s*$",
    re.MULTILINE,
)


@register("GCB-007")
def _fix_gcb007_latest_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``versions/latest`` reference."""
    if _TODO_GCB_LATEST in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _GCB_VERSION_LATEST_RE.finditer(content):
        indent_raw = m.group(1)
        indent_ws = indent_raw[: len(indent_raw) - len(indent_raw.lstrip())]
        edits.append((m.start(), f"{indent_ws}# {_TODO_GCB_LATEST}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── Runner-injection comment-only TODO fixers ────────────────────────
#
# Four parallel fixers for GHA-036 / GL-032 / ADO-030 / JF-032. Each
# rule flags a runner-targeting field (``runs-on:`` / ``tags:`` /
# ``pool:`` / ``agent { label }``) whose value interpolates an
# attacker-controllable expression. The right replacement is a hard-
# coded label or an allowlist guard — neither of which the autofixer
# can synthesize, so the TODO marker points at the canonical shape.

_TODO_GHA_036 = (
    "TODO(pipeline-check GHA-036): hard-code ``runs-on:`` or validate "
    "the input against an allowlist before the job runs. Inlining "
    "${{ inputs.* }} / ${{ github.event.* }} lets a caller route the "
    "job onto any self-hosted runner the org owns"
)
#: Matches a ``runs-on:`` line whose value contains an untrusted-
#: context interpolation. Mirrors the inline-scalar form the rule
#: catches most often. The dict / list shapes are rarer and fall
#: through to ``return None`` rather than risk a misplaced TODO.
_GHA_RUNS_ON_INJECTION_RE = re.compile(
    r"^(\s*)runs-on\s*:\s*[^\n#]*"
    r"\$\{\{\s*(?:"
    r"inputs\.[A-Za-z_][A-Za-z0-9_]*"
    r"|github\.(?:event\.[A-Za-z0-9_.]+|head_ref|ref_name|actor)"
    r")\s*\}\}",
    re.MULTILINE,
)


@register("GHA-036")
def _fix_gha036_runs_on_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``runs-on:`` line that interpolates
    untrusted context.

    Comment-only because the right shape is either a hard-coded
    label or a validated allowlist — both require operator input
    the fixer can't infer.
    """
    if _TODO_GHA_036 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _GHA_RUNS_ON_INJECTION_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_GHA_036}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_GL_032 = (
    "TODO(pipeline-check GL-032): hard-code ``tags:`` to a specific "
    "runner-tag list, or validate the value against an allowlist in "
    "a ``rules:`` guard. Inlining $CI_COMMIT_* / $CI_MERGE_REQUEST_* "
    "lets a pipeline trigger pick which runner pool the job runs on"
)
#: Matches a ``tags:`` line whose right-hand side contains an
#: untrusted CI variable reference. Catches both the inline-list
#: form (``tags: [a, $CI_COMMIT_REF_NAME]``) and the inline-scalar
#: form (``tags: $CI_COMMIT_BRANCH``). The block-list form (``tags:
#: \n  - a\n  - $CI_*``) is matched by ``_GL_BLOCK_TAGS_RE`` below.
_GL_TAGS_INJECTION_RE = re.compile(
    r"^(\s*)tags\s*:\s*[^\n#]*"
    r"\$\{?(?:CI_COMMIT_(?:MESSAGE|DESCRIPTION|TITLE|REF_NAME|BRANCH"
    r"|TAG(?:_MESSAGE)?|AUTHOR)"
    r"|CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)"
    r"|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_(?:NAME|SHA))\}?",
    re.MULTILINE,
)


@register("GL-032")
def _fix_gl032_tags_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``tags:`` line that interpolates
    untrusted CI variables (inline list / scalar form)."""
    if _TODO_GL_032 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _GL_TAGS_INJECTION_RE.finditer(content):
        indent = m.group(1)
        edits.append((m.start(), f"{indent}# {_TODO_GL_032}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_ADO_030 = (
    "TODO(pipeline-check ADO-030): hard-code ``pool:`` (or its "
    "``name:`` / ``demands:`` sub-fields), or validate the value "
    "against an allowlist via a ``condition:`` guard. Inlining "
    "$(Build.*) / $(System.PullRequest.*) / ${{ parameters.X }} lets "
    "a trigger pick which agent pool the job runs on"
)
#: Matches a ``pool:`` / ``name:`` / ``demands:`` line whose RHS
#: contains a runtime SCM macro or a ``${{ parameters.X }}`` template
#: parameter. Mirrors the rule's POOL_TAINT_RE coverage on the
#: inline scalar / list-element shape.
_ADO_POOL_INJECTION_RE = re.compile(
    r"^(\s*-?\s*)(?:pool|name|demands)\s*:\s*[^\n#]*"
    r"(?:"
    r"\$\(\s*(?:Build\.SourceBranch(?:Name)?"
    r"|Build\.SourceVersion(?:Message)?"
    r"|Build\.RequestedFor(?:Email)?"
    r"|Build\.DefinitionName"
    r"|System\.PullRequest\.[A-Za-z]+)\s*\)"
    r"|\$\{\{\s*parameters\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
    r")",
    re.MULTILINE,
)


@register("ADO-030")
def _fix_ado030_pool_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``pool:`` / ``name:`` / ``demands:``
    line that interpolates attacker-controllable input."""
    if _TODO_ADO_030 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _ADO_POOL_INJECTION_RE.finditer(content):
        indent = m.group(1)
        # Strip the leading ``-`` if present so the comment lines up
        # with the YAML key column rather than the list-marker column.
        indent_ws = indent.replace("-", " ")
        edits.append((m.start(), f"{indent_ws}# {_TODO_ADO_030}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_JF_032 = (
    "TODO(pipeline-check JF-032): hard-code agent labels to a "
    "specific pool name, or validate ${params.X} against an "
    "allowlist via a Groovy ``if`` guard before the build starts. "
    "Inlining ${env.BRANCH_NAME} / ${env.CHANGE_BRANCH} / "
    "${params.X} lets the triggerer pick which agent the job runs on"
)
#: Matches a ``label`` directive inside a Groovy ``agent { ... }``
#: block whose string value contains a Groovy interpolation of an
#: untrusted env / params reference. Captures the indent of the
#: enclosing line so the inserted comment lands at the right column.
_JF_AGENT_LABEL_INJECTION_RE = re.compile(
    r"^(\s*)(?:agent\s*\{[^\n}]*)?label\s+\"[^\"\n]*"
    r"\$\{?\s*(?:env\.)?(?:BRANCH_NAME|GIT_BRANCH|TAG_NAME"
    r"|CHANGE_TITLE|CHANGE_BRANCH|CHANGE_AUTHOR(?:_DISPLAY_NAME)?"
    r"|CHANGE_URL|CHANGE_TARGET"
    r"|GIT_AUTHOR_NAME|GIT_AUTHOR_EMAIL"
    r"|GIT_COMMITTER_NAME|GIT_COMMITTER_EMAIL)"
    r"\s*\}?"
    r"|^(\s*)(?:agent\s*\{[^\n}]*)?label\s+\"[^\"\n]*"
    r"\$\{?\s*params\.[A-Za-z_][A-Za-z0-9_]*\s*\}?",
    re.MULTILINE,
)


@register("JF-032")
def _fix_jf032_label_todo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each Groovy ``label "..."`` line that
    interpolates an untrusted Groovy reference."""
    if _TODO_JF_032 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _JF_AGENT_LABEL_INJECTION_RE.finditer(content):
        indent = m.group(1) or m.group(2) or ""
        edits.append((m.start(), f"{indent}// {_TODO_JF_032}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


# ── Helm chart-supply-chain TODO fixers (HELM-001/002/003) ───────────
#
# Helm fixers are comment-only because the structural change each
# rule asks for can't be applied by text-patching ``Chart.yaml``
# alone:
#
# - HELM-001 (apiVersion: v1) needs a v1→v2 schema migration that
#   moves dependencies out of ``requirements.yaml`` and adds
#   ``Chart.lock`` — not a single-line edit.
# - HELM-002 (missing Chart.lock digests) needs ``helm dependency
#   update`` to actually fetch the deps and compute their sha256s.
# - HELM-003 (non-HTTPS dep repo) needs the maintainer to confirm
#   the dep is also published over HTTPS / OCI before the URL flip
#   is safe; rewriting ``http://`` to ``https://`` blindly can
#   break ``helm dependency build``.
#
# In each case the fixer drops a TODO marker above the offending
# line so the change is visible in review and ``--fix`` keeps a
# sensible exit-code story alongside the K8s / Dockerfile fixers.


_TODO_HELM_001 = (
    "TODO(pipeline-check HELM-001): bump to ``apiVersion: v2`` and "
    "migrate any sibling ``requirements.yaml`` entries into the "
    "``dependencies:`` list, then run ``helm dependency update``"
)

# Match the top-level ``apiVersion: v1`` line in Chart.yaml. The
# value capture deliberately rejects whitespace and ``#`` so an
# inline comment doesn't trip the regex.
_HELM_API_V1_RE = re.compile(
    r"^(?P<indent>\s*)apiVersion\s*:\s*[\"']?v1[\"']?\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-001")
def _fix_helm001_api_version(content: str, finding: Finding) -> str | None:
    """Insert a TODO above ``apiVersion: v1`` in Chart.yaml.

    Idempotent via the marker check. Multiple matches in one file
    (rare — a chart should have one ``apiVersion`` key) each get a
    comment above them.
    """
    if _TODO_HELM_001 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_API_V1_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_001}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_HELM_002 = (
    "TODO(pipeline-check HELM-002): commit a ``Chart.lock`` with a "
    "``sha256:`` digest per entry — re-run ``helm dependency update`` "
    "after every change to this list"
)

# Match the ``dependencies:`` key at the top level of Chart.yaml.
# Anchoring to BOL + a single ``dependencies`` key avoids matching
# nested mappings (e.g. a ``spec.dependencies:`` field in some
# chart-of-charts shapes).
_HELM_DEPENDENCIES_RE = re.compile(
    r"^(?P<indent>\s*)dependencies\s*:\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-002")
def _fix_helm002_dependencies_lock(content: str, finding: Finding) -> str | None:
    """Insert a TODO above the ``dependencies:`` key in Chart.yaml.

    Covers all three HELM-002 failure shapes (no Chart.lock at all,
    Chart.lock missing entries, Chart.lock entries without digests)
    by anchoring at the dependency manifest's root rather than a
    specific failure mode in Chart.lock — the human action is the
    same in every case (``helm dependency update``).
    """
    if _TODO_HELM_002 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_DEPENDENCIES_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_002}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)


_TODO_HELM_003 = (
    "TODO(pipeline-check HELM-003): switch this repository to "
    "``https://``, ``oci://``, or a ``file://`` sibling; plaintext "
    "fetch lets an on-path attacker swap the dependency tarball"
)

# Match a ``repository: <url>`` line whose URL is on a non-HTTPS,
# non-OCI, non-file scheme. Only the four common plaintext schemes
# need to fire here; safe URLs simply don't match.
_HELM_PLAINTEXT_REPO_RE = re.compile(
    r"^(?P<indent>\s*)repository\s*:\s*[\"']?"
    r"(?:http|git|ftp|rsync)://[^\s\"'#]*"
    r"[\"']?\s*(?:#[^\n]*)?$",
    re.MULTILINE,
)


@register("HELM-003")
def _fix_helm003_plaintext_repo(content: str, finding: Finding) -> str | None:
    """Insert a TODO above each ``repository: <plaintext-url>`` line.

    Multiple deps on the same chart each get their own comment so a
    review with several offenders is unambiguous.
    """
    if _TODO_HELM_003 in content:
        return None
    edits: list[tuple[int, str]] = []
    for m in _HELM_PLAINTEXT_REPO_RE.finditer(content):
        indent = m.group("indent")
        edits.append((m.start(), f"{indent}# {_TODO_HELM_003}\n"))
    if not edits:
        return None
    return _insert_comment_above(content, edits)
